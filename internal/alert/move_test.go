package alert_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
)

const movedAt = "2026-08-30T13:00:00Z"

func open(t *testing.T) *alertv1.Alert {
	t.Helper()
	raised, err := alert.Raise(decided(), instant(raisedAt))
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	return raised
}

func move(to alert.State, note string) alert.Move {
	return alert.Move{To: to, Note: note, Actor: "analyst", At: instant(movedAt)}
}

func TestAMoveAdvancesTheRevisionAndWritesOneLineOfTrail(t *testing.T) {
	raised := open(t)

	moved, line, err := alert.Apply(raised, move(alert.Acknowledged, ""))
	if err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if moved.GetState() != alertv1.State_STATE_ACKNOWLEDGED {
		t.Errorf("the alert is %s", moved.GetState())
	}
	if moved.GetRevision() != raised.GetRevision()+1 {
		t.Errorf("the revision went %d -> %d", raised.GetRevision(), moved.GetRevision())
	}
	if moved.GetChangedBy() != "analyst" || !moved.GetChangedAt().AsTime().Equal(instant(movedAt)) {
		t.Errorf("the alert was changed by %q at %s", moved.GetChangedBy(), moved.GetChangedAt().AsTime())
	}
	if raised.GetState() != alertv1.State_STATE_OPEN || raised.GetRevision() != 1 {
		t.Error("applying a move changed the alert it was applied to")
	}

	if line.GetFrom() != alertv1.State_STATE_OPEN || line.GetTo() != alertv1.State_STATE_ACKNOWLEDGED {
		t.Errorf("the trail line runs %s -> %s", line.GetFrom(), line.GetTo())
	}
	if line.GetRevision() != moved.GetRevision() || line.GetActor() != "analyst" {
		t.Errorf("the trail line is %q at revision %d", line.GetActor(), line.GetRevision())
	}
}

func TestAnIllegalMoveIsRefusedAndChangesNothing(t *testing.T) {
	investigating, _, err := alert.Apply(open(t), move(alert.InInvestigation, ""))
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}

	if _, _, err := alert.Apply(investigating, move(alert.Acknowledged, "")); err == nil {
		t.Fatal("an investigation stepped backwards to acknowledged")
	}
	if _, _, err := alert.Apply(investigating, move(alert.InInvestigation, "")); !errors.Is(err, alert.ErrNothingAsked) {
		t.Errorf("moving to the state it is already in produced %v", err)
	}
	if _, _, err := alert.Apply(investigating, move("escalated", "")); err == nil {
		t.Error("an invented state was accepted")
	}
}

func TestClosingAsAFalsePositiveNeedsAReasonAndResolvingDoesNot(t *testing.T) {
	if _, _, err := alert.Apply(open(t), move(alert.FalsePositive, "")); !errors.Is(err, alert.ErrNeedsReason) {
		t.Errorf("a false positive with no reason produced %v", err)
	}

	resolved, _, err := alert.Apply(open(t), move(alert.Resolved, ""))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.GetClosure().GetState() != alertv1.State_STATE_RESOLVED {
		t.Errorf("a resolved alert closed as %s", resolved.GetClosure().GetState())
	}
	if resolved.GetClosure().GetClosedBy() != "analyst" {
		t.Errorf("the closure was written by %q", resolved.GetClosure().GetClosedBy())
	}

	if _, _, err := alert.Apply(resolved, move(alert.Open, "")); !errors.Is(err, alert.ErrNeedsReason) {
		t.Errorf("reopening with no reason produced %v", err)
	}

	reopened, _, err := alert.Apply(resolved, move(alert.Open, "the host was not decommissioned after all"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reopened.GetClosure() != nil {
		t.Error("a reopened alert still carries the closure that ended it")
	}
}

func TestAFalsePositiveKeepsTheReasonARuleIsCorrectedFrom(t *testing.T) {
	closed, line, err := alert.Apply(open(t), move(alert.FalsePositive, "the scanner is ours"))
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if closed.GetClosure().GetState() != alertv1.State_STATE_FALSE_POSITIVE {
		t.Errorf("closed as %s", closed.GetClosure().GetState())
	}
	if closed.GetClosure().GetReason() != "the scanner is ours" {
		t.Errorf("the reason was kept as %q", closed.GetClosure().GetReason())
	}
	if line.GetNote() != "the scanner is ours" {
		t.Errorf("the trail carries the note as %q", line.GetNote())
	}
}

func TestTwoPeopleActingAtOnceMeansTheSecondIsToldRatherThanLost(t *testing.T) {
	raised := open(t)

	first, _, err := alert.Apply(raised, alert.Move{To: alert.Acknowledged, Actor: "alice", At: instant(movedAt), Expected: 1})
	if err != nil {
		t.Fatalf("first move: %v", err)
	}

	_, _, err = alert.Apply(first, alert.Move{To: alert.InInvestigation, Actor: "bob", At: instant(movedAt), Expected: 1})
	if !errors.Is(err, alert.ErrMoved) {
		t.Fatalf("a stale revision produced %v", err)
	}
	if !strings.Contains(err.Error(), "revision 2") {
		t.Errorf("the refusal %q does not say where the alert actually is", err)
	}

	if _, _, err := alert.Apply(first, alert.Move{To: alert.InInvestigation, Actor: "bob", At: instant(movedAt)}); err != nil {
		t.Errorf("a move that expected nothing was refused: %v", err)
	}
}

func TestHandingAnAlertOverIsAChangeTheTrailCarries(t *testing.T) {
	raised := open(t)

	assigned, line, err := alert.Apply(raised, alert.Move{Assignee: alert.Assigning("alice"), Actor: "alice", At: instant(movedAt)})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if assigned.GetAssignee() != "alice" {
		t.Errorf("the alert is held by %q", assigned.GetAssignee())
	}
	if assigned.GetState() != raised.GetState() {
		t.Error("assigning an alert changed its state")
	}
	if line.GetFrom() != line.GetTo() || line.GetAssignee() != "alice" {
		t.Errorf("the trail line runs %s -> %s for %q", line.GetFrom(), line.GetTo(), line.GetAssignee())
	}

	if _, _, err := alert.Apply(assigned, alert.Move{Assignee: alert.Assigning("alice"), Actor: "alice", At: instant(movedAt)}); !errors.Is(err, alert.ErrNothingAsked) {
		t.Errorf("assigning to whoever already holds it produced %v", err)
	}

	returned, _, err := alert.Apply(assigned, alert.Move{Assignee: alert.Assigning(""), Actor: "alice", At: instant(movedAt)})
	if err != nil {
		t.Fatalf("hand back: %v", err)
	}
	if returned.GetAssignee() != "" {
		t.Errorf("the alert is still held by %q", returned.GetAssignee())
	}
}

func TestAMoveIsAttributableOrItDoesNotHappen(t *testing.T) {
	_, _, err := alert.Apply(open(t), alert.Move{To: alert.Acknowledged, At: instant(movedAt)})
	if !errors.Is(err, alert.ErrNoActor) {
		t.Errorf("an unattributed move produced %v", err)
	}

	if _, _, err := alert.Apply(open(t), alert.Move{Actor: "analyst", At: instant(movedAt)}); !errors.Is(err, alert.ErrNothingAsked) {
		t.Errorf("a move asking for nothing produced %v", err)
	}
}
