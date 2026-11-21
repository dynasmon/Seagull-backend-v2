package agentfinding_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func reportArriving(sequence uint64, arrived time.Time, condition agentv1.Status_Condition) *agentv1.Status {
	report := fixtures.Report{AgentID: "web-01", Sequence: sequence, At: arrived.Add(-time.Second), Condition: condition}.Status()
	report.Origin.TenantId = "default"
	report.Reception = &eventv1.Reception{IngestTime: timestamppb.New(arrived), Gateway: "gateway-1", BatchId: "status-1"}
	return report
}

func TestAReportIsNamedByWhatTellsOneSourceFromAnotherAndWhenItArrived(t *testing.T) {
	report := reportArriving(41, opened, agentv1.Status_CONDITION_STOPPED)
	heard := agentfinding.HeardOf(report)
	if heard.GetInstallationId() != report.GetInstallationId() || heard.GetBootId() != report.GetRun().GetBootId() ||
		heard.GetSequence() != 41 || !heard.GetIngestTime().AsTime().Equal(opened) || heard.GetGateway() != "gateway-1" ||
		!proto.Equal(heard.GetInterval(), report.GetInterval()) || !heard.GetStopping() ||
		!proto.Equal(heard.GetRunStartedAt(), report.GetRun().GetStartedAt()) || !proto.Equal(heard.GetReportedAt(), report.GetReportedAt()) {
		t.Errorf("the report was named as %v", heard)
	}
	if agentfinding.HeardOf(reportArriving(42, opened, agentv1.Status_CONDITION_RUNNING)).GetStopping() {
		t.Error("a running agent was heard as stopping")
	}
}

func TestASilenceOpensFiveIntervalsAfterTheNewestReportArrivedWhenEverItIsDecided(t *testing.T) {
	newest := agentfinding.HeardOf(reportArriving(41, opened, agentv1.Status_CONDITION_RUNNING))
	if got := agentfinding.SilentFrom(newest); !got.Equal(opened.Add(5 * time.Minute)) {
		t.Fatalf("an agent reporting every minute is silent from %s", got)
	}

	first := agentfinding.Silence("default", "web-01", newest, opened.Add(6*time.Minute))
	later := agentfinding.Silence("default", "web-01", newest, opened.Add(time.Hour))
	if err := agentfinding.Validate(first); err != nil {
		t.Fatalf("a silence the domain made was refused: %v", err)
	}
	if first.GetFindingId() != later.GetFindingId() || !proto.Equal(first.GetOpenedAt(), later.GetOpenedAt()) {
		t.Error("judging one silence again named another finding or another instant")
	}
	if next := agentfinding.Silence("default", "web-01", agentfinding.HeardOf(reportArriving(42, opened, agentv1.Status_CONDITION_RUNNING)), opened); next.GetFindingId() == first.GetFindingId() {
		t.Error("a silence after another report is the same finding")
	}
}

func TestASilenceClosesNoEarlierThanItOpenedAndNamesWhatEndedIt(t *testing.T) {
	newest := agentfinding.HeardOf(reportArriving(41, opened, agentv1.Status_CONDITION_RUNNING))
	open := agentfinding.Silence("default", "web-01", newest, opened.Add(6*time.Minute))
	back := agentfinding.HeardOf(reportArriving(42, opened.Add(20*time.Minute), agentv1.Status_CONDITION_RUNNING))

	closed := agentfinding.Closed(open, agentv1.Finding_CLOSURE_HEARD, back.GetIngestTime().AsTime(), opened.Add(21*time.Minute), back)
	if err := agentfinding.Validate(closed); err != nil {
		t.Fatalf("a closed silence was refused: %v", err)
	}
	if closed.GetFindingId() != open.GetFindingId() || !closed.GetClosedAt().AsTime().Equal(opened.Add(20*time.Minute)) ||
		len(closed.GetReports()) != 2 || closed.GetReports()[1].GetSequence() != 42 || open.GetState() != agentv1.Finding_STATE_OPEN {
		t.Errorf("the silence closed as %v, and the open decision became %v", closed, open.GetState())
	}

	early := agentfinding.Closed(open, agentv1.Finding_CLOSURE_NOT_ADMITTED, opened, opened.Add(7*time.Minute))
	if err := agentfinding.Validate(early); err != nil || !early.GetClosedAt().AsTime().Equal(open.GetOpenedAt().AsTime()) {
		t.Errorf("a silence the registry ended before it opened closed at %s (%v)", early.GetClosedAt().AsTime(), err)
	}

	again := agentfinding.Again(open, opened.Add(25*time.Hour))
	if again.GetDecidedAt().AsTime().Equal(open.GetDecidedAt().AsTime()) || !proto.Equal(again.GetOpenedAt(), open.GetOpenedAt()) || again.GetState() != agentv1.Finding_STATE_OPEN {
		t.Errorf("deciding an open silence again made %v", again)
	}
}
