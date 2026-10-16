package assessmentstore_test

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

	"github.com/dynasmon/Seagull-backend-v2/internal/assessmentstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

var arrived = time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)

type reader struct {
	records   []assessmentstore.Record
	committed bool
}

func (r *reader) Consume(ctx context.Context, deliver assessmentstore.Deliver) error {
	if err := deliver(ctx, r.records); err != nil {
		return err
	}
	r.committed = true
	return nil
}

type stored struct {
	failures int
	rows     [][]assessmentstore.Row
}

func (s *stored) Store(_ context.Context, rows []assessmentstore.Row) error {
	if s.failures > 0 {
		s.failures--
		return errors.New("the store is unavailable")
	}
	s.rows = append(s.rows, slices.Clone(rows))
	return nil
}

type refuser struct{ refused [][]assessmentstore.Refused }

func (r *refuser) Publish(_ context.Context, refused []assessmentstore.Refused) error {
	r.refused = append(r.refused, slices.Clone(refused))
	return nil
}

func projector(t *testing.T, source assessmentstore.Source, sink assessmentstore.Sink, quarantine assessmentstore.Quarantine) *assessmentstore.Projector {
	t.Helper()
	built, err := assessmentstore.NewProjector(assessmentstore.ProjectorOptions{
		Source:        source,
		Sink:          sink,
		Quarantine:    quarantine,
		Metrics:       assessmentstore.NewMetrics(metrics.New("test")),
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

func admitted(id string, revision uint64) *assessmentv1.Assessment {
	assessed := fixtures.Posture{AssessmentID: id, AgentID: "web-01", Revision: revision, At: arrived.Add(-time.Minute)}.Assessment()
	assessed.Origin.TenantId = "acme"
	assessed.Reception = &eventv1.Reception{IngestTime: timestamppb.New(arrived), Gateway: "gateway-a", BatchId: "assessment-1"}
	return assessed
}

func fetched(t *testing.T, made proto.Message) assessmentstore.Record {
	t.Helper()
	payload, err := proto.Marshal(made)
	if err != nil {
		t.Fatalf("encode an assessment: %v", err)
	}
	return assessmentstore.Record{Partition: 1, Offset: 42, Key: []byte("web-01"), Value: payload}
}

func TestAnAssessmentIsKeptWithItsOutcomesCountedAndTheBytesItWasPublishedAs(t *testing.T) {
	record := fetched(t, admitted("asm-0000000007", 7))
	source, sink := &reader{records: []assessmentstore.Record{record}}, &stored{}

	if err := projector(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if !source.committed || len(sink.rows) != 1 || len(sink.rows[0]) != 1 {
		t.Fatalf("the batch folded into %v, committed %t", sink.rows, source.committed)
	}
	row := sink.rows[0][0]
	if row.TenantID != "acme" || row.AgentID != "web-01" || row.AssessmentID != "asm-0000000007" || !row.IngestTime.Equal(arrived) ||
		!row.AssessedAt.Equal(arrived.Add(-time.Minute)) || row.PolicyID != "linux-baseline" || row.PolicyRevision != 7 {
		t.Errorf("the assessment folded into %+v", row)
	}
	if row.Checks != 3 || row.Passed != 1 || row.Failed != 1 || row.NotApplicable != 1 || row.Errors != 0 || row.Unsupported != 0 {
		t.Errorf("the outcomes were counted as %+v", row)
	}
	if !bytes.Equal(row.Assessment, record.Value) {
		t.Error("the stored assessment is not the one the gateway published")
	}
}

func TestAnAssessmentThatAnswersNothingIsKept(t *testing.T) {
	empty := admitted("asm-0000000008", 8)
	empty.Results = nil
	sink := &stored{}

	if err := projector(t, &reader{records: []assessmentstore.Record{fetched(t, empty)}}, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if len(sink.rows) != 1 || sink.rows[0][0].Checks != 0 {
		t.Fatalf("an assessment saying its policy asks for no checks folded into %v", sink.rows)
	}
}

func TestWhatIsNotAnAssessmentTheContractAdmitsIsQuarantinedAndTheRestIsKept(t *testing.T) {
	unstamped := admitted("asm-0000000002", 2)
	unstamped.Reception = nil
	broken := admitted("asm-0000000003", 3)
	broken.Results[0].Outcome = assessmentv1.Outcome_OUTCOME_UNSPECIFIED

	source := &reader{records: []assessmentstore.Record{
		{Partition: 1, Offset: 1, Value: []byte{0xff, 0xff}},
		fetched(t, broken),
		fetched(t, unstamped),
		fetched(t, admitted("asm-0000000004", 4)),
	}}
	sink, quarantine := &stored{}, &refuser{}

	if err := projector(t, source, sink, quarantine).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if len(sink.rows) != 1 || len(sink.rows[0]) != 1 || sink.rows[0][0].PolicyRevision != 4 {
		t.Fatalf("the store holds %v", sink.rows)
	}
	var reasons []string
	for _, refused := range quarantine.refused[0] {
		reasons = append(reasons, refused.Reason)
	}
	if !slices.Equal(reasons, []string{assessmentstore.ReasonUndecodable, assessmentstore.ReasonContractViolation, assessmentstore.ReasonUnstorable}) {
		t.Fatalf("the quarantine holds %v", reasons)
	}
}

func TestAStoreOutageIsRetriedAndNeverSteppedOver(t *testing.T) {
	source, sink := &reader{records: []assessmentstore.Record{fetched(t, admitted("asm-0000000005", 5))}}, &stored{failures: 3}

	if err := projector(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if !source.committed || len(sink.rows) != 1 {
		t.Fatalf("after an outage the store holds %v and the source committed %t", sink.rows, source.committed)
	}

	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	never := &reader{records: []assessmentstore.Record{fetched(t, admitted("asm-0000000006", 6))}}
	if err := projector(t, never, &stored{failures: 1 << 30}, &refuser{}).Run(stopped); err == nil || never.committed {
		t.Fatal("a stopping projector advanced past a batch the store never took")
	}
}
