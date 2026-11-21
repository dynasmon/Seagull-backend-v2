package agentfindingstore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentfindingstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

var silentAt = time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC)

type reader struct {
	records   []agentfindingstore.Record
	committed bool
}

func (r *reader) Consume(ctx context.Context, deliver agentfindingstore.Deliver) error {
	if err := deliver(ctx, r.records); err != nil {
		return err
	}
	r.committed = true
	return nil
}

type stored struct {
	failures int
	rows     [][]agentfindingstore.Row
}

func (s *stored) Store(_ context.Context, rows []agentfindingstore.Row) error {
	if s.failures > 0 {
		s.failures--
		return errors.New("the store is unavailable")
	}
	s.rows = append(s.rows, slices.Clone(rows))
	return nil
}

type refuser struct{ refused [][]agentfindingstore.Refused }

func (r *refuser) Publish(_ context.Context, refused []agentfindingstore.Refused) error {
	r.refused = append(r.refused, slices.Clone(refused))
	return nil
}

func writer(t *testing.T, source agentfindingstore.Source, sink agentfindingstore.Sink, quarantine agentfindingstore.Quarantine) *agentfindingstore.Writer {
	t.Helper()
	built, err := agentfindingstore.NewWriter(agentfindingstore.WriterOptions{
		Source:        source,
		Sink:          sink,
		Quarantine:    quarantine,
		Metrics:       agentfindingstore.NewMetrics(metrics.New("test")),
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

func silence(sequence uint64) *agentv1.Finding {
	reported := silentAt.Add(-5 * time.Minute)
	return &agentv1.Finding{
		SchemaVersion:  agentfinding.SchemaVersion,
		FindingId:      agentfinding.ID("acme", "web-01", agentv1.Finding_KIND_SILENCE, "boot", "41"),
		TenantId:       "acme",
		AgentId:        "web-01",
		Kind:           agentv1.Finding_KIND_SILENCE,
		State:          agentv1.Finding_STATE_OPEN,
		OpenedAt:       timestamppb.New(silentAt),
		LastObservedAt: timestamppb.New(silentAt),
		Observations:   1,
		DecidedAt:      timestamppb.New(silentAt.Add(3 * time.Second)),
		Reports: []*agentv1.Heard{{
			InstallationId: "installation-a",
			BootId:         "boot",
			Sequence:       sequence,
			ReportedAt:     timestamppb.New(reported),
			IngestTime:     timestamppb.New(reported.Add(20 * time.Millisecond)),
			Gateway:        "gateway-a",
			Interval:       durationpb.New(time.Minute),
		}},
	}
}

func fetched(t *testing.T, made proto.Message) agentfindingstore.Record {
	t.Helper()
	payload, err := proto.Marshal(made)
	if err != nil {
		t.Fatalf("encode a finding: %v", err)
	}
	return agentfindingstore.Record{Partition: 1, Offset: 42, Key: []byte("web-01"), Value: payload}
}

func TestADecisionIsStoredWithTheBytesItWasPublishedAs(t *testing.T) {
	record := fetched(t, silence(41))
	source, sink := &reader{records: []agentfindingstore.Record{record}}, &stored{}

	if err := writer(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("store the batch: %v", err)
	}
	if !source.committed || len(sink.rows) != 1 || len(sink.rows[0]) != 1 {
		t.Fatalf("the batch was stored as %v, committed %t", sink.rows, source.committed)
	}
	row := sink.rows[0][0]
	if row.TenantID != "acme" || row.AgentID != "web-01" || row.FindingID != silence(41).GetFindingId() ||
		row.Kind != "silence" || row.State != "open" || row.Closure != "unspecified" ||
		!row.OpenedAt.Equal(silentAt) || !row.LastObservedAt.Equal(silentAt) || row.Observations != 1 ||
		!row.ClosedAt.IsZero() || !row.DecidedAt.Equal(silentAt.Add(3*time.Second)) {
		t.Errorf("the decision was stored as %+v", row)
	}
	if !bytes.Equal(row.Finding, record.Value) {
		t.Error("the stored decision is not the one that was published")
	}
}

func TestWhatIsNotADecisionTheContractAdmitsIsQuarantinedAndTheRestIsStored(t *testing.T) {
	unnamed := silence(2)
	unnamed.FindingId = ""

	source := &reader{records: []agentfindingstore.Record{
		{Partition: 1, Offset: 1, Value: []byte{0xff, 0xff}},
		fetched(t, unnamed),
		fetched(t, silence(4)),
	}}
	sink, quarantine := &stored{}, &refuser{}

	if err := writer(t, source, sink, quarantine).Run(context.Background()); err != nil {
		t.Fatalf("store the batch: %v", err)
	}
	if len(sink.rows) != 1 || len(sink.rows[0]) != 1 || sink.rows[0][0].FindingID != silence(4).GetFindingId() {
		t.Fatalf("the store holds %v", sink.rows)
	}
	var reasons []string
	for _, refused := range quarantine.refused[0] {
		reasons = append(reasons, refused.Reason)
	}
	if !slices.Equal(reasons, []string{agentfindingstore.ReasonUndecodable, agentfindingstore.ReasonContractViolation}) {
		t.Fatalf("the quarantine holds %v", reasons)
	}
}

func TestAStoreOutageIsRetriedAndNeverSteppedOver(t *testing.T) {
	source, sink := &reader{records: []agentfindingstore.Record{fetched(t, silence(5))}}, &stored{failures: 3}

	if err := writer(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("store the batch: %v", err)
	}
	if !source.committed || len(sink.rows) != 1 {
		t.Fatalf("after an outage the store holds %v and the source committed %t", sink.rows, source.committed)
	}

	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	never := &reader{records: []agentfindingstore.Record{fetched(t, silence(6))}}
	if err := writer(t, never, &stored{failures: 1 << 30}, &refuser{}).Run(stopped); err == nil || never.committed {
		t.Fatal("a stopping writer advanced past a batch the store never took")
	}
}
