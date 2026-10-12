package statusstore_test

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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/statusstore"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

var arrived = time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)

type reader struct {
	records   []statusstore.Record
	committed bool
}

func (r *reader) Consume(ctx context.Context, deliver statusstore.Deliver) error {
	if err := deliver(ctx, r.records); err != nil {
		return err
	}
	r.committed = true
	return nil
}

type stored struct {
	failures int
	rows     [][]statusstore.Row
}

func (s *stored) Store(_ context.Context, rows []statusstore.Row) error {
	if s.failures > 0 {
		s.failures--
		return errors.New("the store is unavailable")
	}
	s.rows = append(s.rows, slices.Clone(rows))
	return nil
}

type refuser struct{ refused [][]statusstore.Refused }

func (r *refuser) Publish(_ context.Context, refused []statusstore.Refused) error {
	r.refused = append(r.refused, slices.Clone(refused))
	return nil
}

func projector(t *testing.T, source statusstore.Source, sink statusstore.Sink, quarantine statusstore.Quarantine) *statusstore.Projector {
	t.Helper()
	built, err := statusstore.NewProjector(statusstore.ProjectorOptions{
		Source:        source,
		Sink:          sink,
		Quarantine:    quarantine,
		Metrics:       statusstore.NewMetrics(metrics.New("test")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 2 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build the projector: %v", err)
	}
	return built
}

func admitted(sequence uint64) *agentv1.Status {
	report := fixtures.Report{AgentID: "web-01", Sequence: sequence, At: arrived.Add(-time.Second), Condition: agentv1.Status_CONDITION_DEGRADED}.Status()
	report.Origin.TenantId = "acme"
	report.Reception = &eventv1.Reception{IngestTime: timestamppb.New(arrived), Gateway: "gateway-a", BatchId: "status-1"}
	return report
}

func fetched(t *testing.T, made proto.Message) statusstore.Record {
	t.Helper()
	payload, err := proto.Marshal(made)
	if err != nil {
		t.Fatalf("encode a report: %v", err)
	}
	return statusstore.Record{Partition: 1, Offset: 42, Key: []byte("web-01"), Value: payload}
}

func TestAReportIsFoldedWithTheBytesItWasPublishedAs(t *testing.T) {
	record := fetched(t, admitted(7))
	source, sink := &reader{records: []statusstore.Record{record}}, &stored{}

	if err := projector(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if !source.committed || len(sink.rows) != 1 || len(sink.rows[0]) != 1 {
		t.Fatalf("the batch folded into %v, committed %t", sink.rows, source.committed)
	}
	row := sink.rows[0][0]
	if row.TenantID != "acme" || row.AgentID != "web-01" || !row.IngestTime.Equal(arrived) || row.Sequence != 7 ||
		row.Condition != "degraded" || row.IntervalMillis != 60_000 || row.BuildVersion != "v0.1.0" ||
		row.InstallationID == "" || row.BootID == "" || !row.ReportedAt.Equal(arrived.Add(-time.Second)) {
		t.Errorf("the report folded into %+v", row)
	}
	if !bytes.Equal(row.Report, record.Value) {
		t.Error("the stored report is not the one the gateway published")
	}
}

func TestWhatIsNotAReportTheContractAdmitsIsQuarantinedAndTheRestIsFolded(t *testing.T) {
	unstamped := admitted(2)
	unstamped.Reception = nil
	broken := admitted(3)
	broken.Interval = nil

	source := &reader{records: []statusstore.Record{
		{Partition: 1, Offset: 1, Value: []byte{0xff, 0xff}},
		fetched(t, broken),
		fetched(t, unstamped),
		fetched(t, admitted(4)),
	}}
	sink, quarantine := &stored{}, &refuser{}

	if err := projector(t, source, sink, quarantine).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if len(sink.rows) != 1 || len(sink.rows[0]) != 1 || sink.rows[0][0].Sequence != 4 {
		t.Fatalf("the store holds %v", sink.rows)
	}
	var reasons []string
	for _, refused := range quarantine.refused[0] {
		reasons = append(reasons, refused.Reason)
	}
	if !slices.Equal(reasons, []string{statusstore.ReasonUndecodable, statusstore.ReasonContractViolation, statusstore.ReasonUnstorable}) {
		t.Fatalf("the quarantine holds %v", reasons)
	}
}

func TestAStoreOutageIsRetriedAndNeverSteppedOver(t *testing.T) {
	source, sink := &reader{records: []statusstore.Record{fetched(t, admitted(5))}}, &stored{failures: 3}

	if err := projector(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if !source.committed || len(sink.rows) != 1 {
		t.Fatalf("after an outage the store holds %v and the source committed %t", sink.rows, source.committed)
	}

	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	never := &reader{records: []statusstore.Record{fetched(t, admitted(6))}}
	if err := projector(t, never, &stored{failures: 1 << 30}, &refuser{}).Run(stopped); err == nil || never.committed {
		t.Fatal("a stopping projector advanced past a batch the store never took")
	}
}
