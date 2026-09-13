package advisorystore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

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

type store struct {
	attempts int
	failures int
	stored   []Projection
}

func (s *store) Store(_ context.Context, projected Projection) error {
	s.attempts++
	if s.failures != 0 {
		if s.failures > 0 {
			s.failures--
		}
		return errors.New("the store is unavailable")
	}
	s.stored = append(s.stored, projected)
	return nil
}

type refuser struct{ refused [][]Refused }

func (r *refuser) Publish(_ context.Context, refused []Refused) error {
	r.refused = append(r.refused, slices.Clone(refused))
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

func consumed(t *testing.T, made proto.Message) Record {
	t.Helper()
	payload, err := proto.Marshal(made)
	if err != nil {
		t.Fatalf("encode a record: %v", err)
	}
	return Record{Partition: 0, Offset: 7, Value: payload}
}

func TestAnAdvisoryAndTheSyncAccountingForItAreStoredTogether(t *testing.T) {
	source := &reader{records: []Record{consumed(t, advised(advisory())), consumed(t, synced(sync()))}}
	sink := &store{}

	if err := writer(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("write the batch: %v", err)
	}
	if !source.committed {
		t.Fatal("the source advanced past a batch it was not told was durable")
	}
	if len(sink.stored) != 1 || len(sink.stored[0].Advisories) != 1 || len(sink.stored[0].Affected) != 2 || len(sink.stored[0].Syncs) != 1 {
		t.Fatalf("stored %+v", sink.stored)
	}
}

func TestARecordThisBuildCannotReadIsQuarantinedAndTheRestIsStored(t *testing.T) {
	unproven := advisory()
	unproven.Provenance.Digest = ""

	source := &reader{records: []Record{
		{Partition: 0, Offset: 1, Value: []byte{0xff, 0xff, 0xff}},
		consumed(t, advised(unproven)),
		consumed(t, advised(advisory())),
	}}
	sink := &store{}
	quarantine := &refuser{}

	if err := writer(t, source, sink, quarantine).Run(context.Background()); err != nil {
		t.Fatalf("write the batch: %v", err)
	}
	if len(sink.stored[0].Advisories) != 1 {
		t.Fatalf("one good record stored as %d advisories", len(sink.stored[0].Advisories))
	}
	var reasons []string
	for _, entry := range quarantine.refused[0] {
		reasons = append(reasons, entry.Reason)
	}
	if !slices.Equal(reasons, []string{ReasonUndecodable, ReasonContractViolation}) {
		t.Fatalf("the refused records were put aside as %v", reasons)
	}
}

func TestAnAdvisoryWithATimeThePlatformCannotHoldIsRefusedWithEveryPackageItNames(t *testing.T) {
	distant := advisory()
	distant.Withdrawn = timestamppb.New(time.Date(3000, time.January, 1, 0, 0, 0, 0, time.UTC))

	sink := &store{}
	quarantine := &refuser{}
	if err := writer(t, &reader{records: []Record{consumed(t, advised(distant))}}, sink, quarantine).Run(context.Background()); err != nil {
		t.Fatalf("write the batch: %v", err)
	}
	if len(sink.stored) != 0 {
		t.Fatalf("an advisory the platform cannot hold reached the store as %+v", sink.stored)
	}
	if quarantine.refused[0][0].Reason != ReasonContractViolation {
		t.Fatalf("the advisory was put aside as %q", quarantine.refused[0][0].Reason)
	}
}

func TestABatchIsRetriedUntilItIsDurableAndTheSourceWaits(t *testing.T) {
	source := &reader{records: []Record{consumed(t, advised(advisory()))}}
	sink := &store{failures: 2}

	if err := writer(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("write the batch: %v", err)
	}
	if sink.attempts != 3 || !source.committed {
		t.Fatalf("the batch was written %d times and committed %v", sink.attempts, source.committed)
	}
}

func TestAStoppedWriterDoesNotAdvancePastABatchItCouldNotStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &reader{records: []Record{consumed(t, advised(advisory()))}}

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if err := writer(t, source, &store{failures: -1}, &refuser{}).Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("a stopped writer returned %v", err)
	}
	if source.committed {
		t.Fatal("the source advanced past a batch that never became durable")
	}
}

func TestTheWriterRefusesAnIncompleteComposition(t *testing.T) {
	complete := WriterOptions{
		Source:        &reader{},
		Sink:          &store{},
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
