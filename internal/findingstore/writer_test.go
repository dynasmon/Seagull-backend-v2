package findingstore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// Advances only when deliver returns nil, which is the whole of what this
// capability asks of a backbone.
type reader struct {
	records   []Record
	committed bool
}

func (r *reader) Consume(ctx context.Context, deliver Deliver) error {
	if err := deliver(ctx, r.records); err != nil {
		return err
	}
	r.committed = true
	return nil
}

type stored struct {
	attempts    int
	failures    int
	findings    []FindingRow
	assessments []AssessmentRow
}

func (s *stored) Store(_ context.Context, findings []FindingRow, assessments []AssessmentRow) error {
	s.attempts++
	if s.failures != 0 {
		if s.failures > 0 {
			s.failures--
		}
		return errors.New("the store is unavailable")
	}
	s.findings = append(s.findings, findings...)
	s.assessments = append(s.assessments, assessments...)
	return nil
}

type refuser struct{ refused []Refused }

func (r *refuser) Publish(_ context.Context, refused []Refused) error {
	r.refused = append(r.refused, refused...)
	return nil
}

func writer(t *testing.T, source Source, sink Sink, quarantine Quarantine) *Writer {
	t.Helper()
	built, err := NewWriter(WriterOptions{
		Source:        source,
		Sink:          sink,
		Quarantine:    quarantine,
		Metrics:       NewMetrics(metrics.New("test")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 2 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build the writer: %v", err)
	}
	return built
}

func fetched(t *testing.T, offset int64, made *vulnerabilityv1.FindingRecord) Record {
	t.Helper()
	payload, err := proto.Marshal(made)
	if err != nil {
		t.Fatalf("encode a record: %v", err)
	}
	return Record{Partition: 2, Offset: offset, Key: []byte("web-01"), Value: payload}
}

func TestDecisionsAndTheirAssessmentAreStoredAndThenTheSourceAdvances(t *testing.T) {
	decision := fixtures.Decision{AgentID: "web-01", DecidedAt: decidedAt}
	source := &reader{records: []Record{
		fetched(t, 10, decision.Record()),
		fetched(t, 11, fixtures.Decision{AgentID: "web-01", Vulnerability: "CVE-2024-5535", DecidedAt: decidedAt}.Record()),
		fetched(t, 12, decision.Assessment(2, 0)),
	}}
	sink := &stored{}

	if err := writer(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("write the batch: %v", err)
	}
	if !source.committed {
		t.Fatal("the source advanced past a batch it was not told was durable")
	}
	if len(sink.findings) != 2 || len(sink.assessments) != 1 {
		t.Fatalf("the batch was stored as %d findings and %d assessments", len(sink.findings), len(sink.assessments))
	}
	if string(sink.findings[0].Record) != string(source.records[0].Value) {
		t.Error("a finding was stored without the record the matcher published")
	}
}

func TestARecordThisBuildCannotReadIsQuarantinedAndTheRestIsStored(t *testing.T) {
	malformed := fixtures.Decision{AgentID: "web-01", DecidedAt: decidedAt}.Record()
	malformed.GetFinding().ItemId = "libssl3"

	source := &reader{records: []Record{
		{Partition: 1, Offset: 1, Value: []byte{0xff, 0xff, 0xff}},
		fetched(t, 2, malformed),
		fetched(t, 3, fixtures.Decision{AgentID: "web-01", DecidedAt: decidedAt}.Record()),
	}}
	sink := &stored{}
	quarantine := &refuser{}

	if err := writer(t, source, sink, quarantine).Run(context.Background()); err != nil {
		t.Fatalf("write the batch: %v", err)
	}
	if len(sink.findings) != 1 {
		t.Fatalf("one good record was stored as %d findings", len(sink.findings))
	}
	var reasons []string
	for _, entry := range quarantine.refused {
		reasons = append(reasons, entry.Reason)
	}
	if !slices.Equal(reasons, []string{ReasonUndecodable, ReasonContractViolation}) {
		t.Fatalf("the refused records were put aside as %v", reasons)
	}
	if quarantine.refused[1].Offset != 2 || string(quarantine.refused[1].Value) != string(source.records[1].Value) {
		t.Fatalf("a refused record was put aside as %+v, without the bytes and position it came with", quarantine.refused[1])
	}
}

func TestABatchIsRetriedUntilItIsDurableAndTheSourceWaits(t *testing.T) {
	source := &reader{records: []Record{fetched(t, 1, fixtures.Decision{DecidedAt: decidedAt}.Record())}}
	sink := &stored{failures: 2}

	if err := writer(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("write the batch: %v", err)
	}
	if sink.attempts != 3 || !source.committed {
		t.Fatalf("the batch was written in %d attempts and the source advanced: %t", sink.attempts, source.committed)
	}
}

func TestAStoppedWriterDoesNotAdvancePastABatchItCouldNotStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &reader{records: []Record{fetched(t, 1, fixtures.Decision{DecidedAt: decidedAt}.Record())}}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	if err := writer(t, source, &stored{failures: -1}, &refuser{}).Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("a stopped writer returned %v", err)
	}
	if source.committed {
		t.Fatal("the source advanced past a batch that never became durable")
	}
}

func TestTheWriterRefusesAnIncompleteComposition(t *testing.T) {
	complete := WriterOptions{
		Source:        &reader{},
		Sink:          &stored{},
		Quarantine:    &refuser{},
		Metrics:       NewMetrics(metrics.New("test")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Second,
		MaxRetryDelay: time.Minute,
	}
	for name, breaking := range map[string]func(*WriterOptions){
		"no source":     func(o *WriterOptions) { o.Source = nil },
		"no sink":       func(o *WriterOptions) { o.Sink = nil },
		"no quarantine": func(o *WriterOptions) { o.Quarantine = nil },
		"no metrics":    func(o *WriterOptions) { o.Metrics = nil },
		"no logger":     func(o *WriterOptions) { o.Logger = nil },
		"no budget":     func(o *WriterOptions) { o.WriteTimeout = 0 },
		"upside down":   func(o *WriterOptions) { o.MaxRetryDelay = time.Millisecond },
	} {
		t.Run(name, func(t *testing.T) {
			options := complete
			breaking(&options)
			if _, err := NewWriter(options); err == nil {
				t.Fatal("the writer was built")
			}
		})
	}
}
