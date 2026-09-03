package incident_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

func opened(t *testing.T) *incidentv1.Incident {
	t.Helper()
	one, err := incident.Raise(correlated(0), raisedAt)
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	return one
}

func move(to incident.State, actor string) incident.Move {
	return incident.Move{To: to, Actor: actor, At: raisedAt.Add(time.Minute)}
}

func TestAMoveAdvancesTheRevisionAndWritesOneLineOfTrail(t *testing.T) {
	one := opened(t)

	moved, line, err := incident.Apply(one, move(incident.Acknowledged, "dev-analyst"))
	if err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if state, _ := incident.FromWire(moved.GetState()); state != incident.Acknowledged {
		t.Errorf("the incident is %s", state)
	}
	if moved.GetRevision() != one.GetRevision()+1 || moved.GetChangedBy() != "dev-analyst" {
		t.Errorf("revision %d, changed by %q", moved.GetRevision(), moved.GetChangedBy())
	}
	if line.GetFrom() != one.GetState() || line.GetTo() != moved.GetState() {
		t.Error("the trail does not say where the incident came from")
	}
	if line.GetRevision() != moved.GetRevision() || line.GetIncidentId() != one.GetIncidentId() {
		t.Error("the line of trail is not about the move that was made")
	}
	if one.GetRevision() != 1 {
		t.Error("applying a move rewrote the incident it was decided against")
	}
}

func TestAnIllegalMoveIsRefusedAndChangesNothing(t *testing.T) {
	one := opened(t)
	one.State = incident.InInvestigation.Wire()

	if _, _, err := incident.Apply(one, move(incident.Acknowledged, "dev-analyst")); !errors.Is(err, incident.ErrIllegalMove) {
		t.Fatalf("stepping an investigation backwards was refused as %v", err)
	}
	if _, _, err := incident.Apply(one, move(incident.InInvestigation, "dev-analyst")); !errors.Is(err, incident.ErrNothingAsked) {
		t.Fatalf("a move to the state it is already in was refused as %v", err)
	}
}

func TestDismissingAStoryNeedsAReasonAndResolvingDoesNot(t *testing.T) {
	if _, _, err := incident.Apply(opened(t), move(incident.Resolved, "dev-analyst")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, _, err := incident.Apply(opened(t), move(incident.FalsePositive, "dev-analyst")); !errors.Is(err, incident.ErrNeedsReason) {
		t.Fatalf("a story dismissed with no reason was refused as %v", err)
	}

	dismissed := move(incident.FalsePositive, "dev-analyst")
	dismissed.Note = "the two events were one operator retrying"
	closed, _, err := incident.Apply(opened(t), dismissed)
	if err != nil {
		t.Fatalf("dismiss: %v", err)
	}
	if closed.GetClosure().GetReason() != dismissed.Note || closed.GetClosure().GetClosedBy() != "dev-analyst" {
		t.Error("the closure does not carry what a correlation rule would be corrected from")
	}

	reopening := incident.Move{To: incident.Open, Actor: "dev-admin", At: raisedAt.Add(time.Hour)}
	if _, _, err := incident.Apply(closed, reopening); !errors.Is(err, incident.ErrNeedsReason) {
		t.Fatalf("reopening with no reason was refused as %v", err)
	}
	reopening.Note = "the second session came from another address"
	reopened, _, err := incident.Apply(closed, reopening)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reopened.GetClosure() != nil {
		t.Error("a reopened incident still says it is closed")
	}
}

func TestTwoPeopleActingAtOnceMeansTheSecondIsToldRatherThanLost(t *testing.T) {
	one := opened(t)

	first := move(incident.Acknowledged, "dev-analyst")
	first.Expected = 1
	moved, _, err := incident.Apply(one, first)
	if err != nil {
		t.Fatalf("acknowledge: %v", err)
	}

	second := move(incident.InInvestigation, "dev-admin")
	second.Expected = 1
	if _, _, err := incident.Apply(moved, second); !errors.Is(err, incident.ErrMoved) {
		t.Fatalf("a stale revision was refused as %v", err)
	}
}

func TestHandingAStoryOverIsAChangeTheTrailCarries(t *testing.T) {
	held, line, err := incident.Apply(opened(t), incident.Move{
		Assignee: incident.Assigning("dev-analyst"),
		Actor:    "dev-admin",
		At:       raisedAt.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if held.GetAssignee() != "dev-analyst" {
		t.Errorf("the incident is held by %q", held.GetAssignee())
	}
	if state, _ := incident.FromWire(held.GetState()); state != incident.Open {
		t.Errorf("assigning moved the incident to %s", state)
	}
	if line.GetFrom() != line.GetTo() || line.GetActor() != "dev-admin" {
		t.Error("the trail does not say who handed the incident over")
	}

	if _, _, err := incident.Apply(held, incident.Move{
		Assignee: incident.Assigning("dev-analyst"),
		Actor:    "dev-admin",
		At:       raisedAt.Add(time.Hour),
	}); !errors.Is(err, incident.ErrNothingAsked) {
		t.Errorf("assigning it to whoever already holds it was refused as %v", err)
	}
}

func TestAMoveIsAttributableOrItDoesNotHappen(t *testing.T) {
	if _, _, err := incident.Apply(opened(t), incident.Move{To: incident.Acknowledged}); !errors.Is(err, incident.ErrNoActor) {
		t.Fatalf("an unattributed move was refused as %v", err)
	}
	if _, _, err := incident.Apply(opened(t), move("archived", "dev-analyst")); !errors.Is(err, incident.ErrUnknownState) {
		t.Fatalf("a state nobody declared was refused as %v", err)
	}
}

func TestMovingAnIncidentTouchesNothingItWasMadeFrom(t *testing.T) {
	one := opened(t)

	dismissed := move(incident.FalsePositive, "dev-analyst")
	dismissed.Note = "one operator retrying"
	closed, _, err := incident.Apply(one, dismissed)
	if err != nil {
		t.Fatalf("dismiss: %v", err)
	}

	if closed.GetDetectionId() != one.GetDetectionId() || closed.GetRulesetId() != one.GetRulesetId() {
		t.Error("closing a story changed what told it")
	}
	if len(closed.GetStages()) != len(one.GetStages()) {
		t.Fatalf("closing a story left %d stages", len(closed.GetStages()))
	}
	for index, stage := range closed.GetStages() {
		was := one.GetStages()[index]
		if stage.GetEventId() != was.GetEventId() || !stage.GetEventTime().AsTime().Equal(was.GetEventTime().AsTime()) {
			t.Errorf("stage %d named %q after the incident was closed", index, stage.GetEventId())
		}
	}
	if closed.GetConfidence() != one.GetConfidence() || closed.GetSeverity() != one.GetSeverity() {
		t.Error("closing a story changed what the platform measured about it")
	}
}
