package alert_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
)

func TestTriageRunsForwardsAndTheOnlyWayBackIsOutOfAnEnding(t *testing.T) {
	legal := map[alert.State][]alert.State{
		alert.Open:            {alert.Acknowledged, alert.InInvestigation, alert.Resolved, alert.FalsePositive},
		alert.Acknowledged:    {alert.InInvestigation, alert.Resolved, alert.FalsePositive},
		alert.InInvestigation: {alert.Resolved, alert.FalsePositive},
		alert.Resolved:        {alert.Open},
		alert.FalsePositive:   {alert.Open},
	}

	for _, from := range alert.States() {
		for _, to := range alert.States() {
			want := slices.Contains(legal[from], to)
			if got := alert.Legal(from, to); got != want {
				t.Errorf("%s -> %s is %v and should be %v", from, to, got, want)
			}
		}
		if slices.Contains(alert.Reachable(from), from) {
			t.Errorf("%s reaches itself", from)
		}
	}
}

func TestAnEndingIsNotAnAlertStateThatCanBeSteppedIntoSideways(t *testing.T) {
	if alert.Legal(alert.Resolved, alert.FalsePositive) {
		t.Error("a resolved alert became a false positive without being reopened")
	}
	if alert.Legal(alert.FalsePositive, alert.Resolved) {
		t.Error("a false positive was resolved without being reopened")
	}
	if alert.Legal(alert.Acknowledged, alert.Open) {
		t.Error("an acknowledged alert was un-acknowledged")
	}
	if alert.Legal(alert.InInvestigation, alert.Acknowledged) {
		t.Error("an investigation stepped backwards")
	}
}

func TestResolvedAndFalsePositiveAreBothEndingsAndOnlyOneNeedsExplaining(t *testing.T) {
	if !alert.Resolved.Closed() || !alert.FalsePositive.Closed() {
		t.Fatal("an ending does not report itself closed")
	}
	for _, open := range []alert.State{alert.Open, alert.Acknowledged, alert.InInvestigation} {
		if open.Closed() {
			t.Errorf("%s reports itself closed", open)
		}
	}

	if alert.Explains(alert.Open, alert.Resolved) {
		t.Error("resolving an open alert was made to need a reason")
	}
	if !alert.Explains(alert.Open, alert.FalsePositive) {
		t.Error("calling an alert a false positive needs no reason")
	}
	for _, ending := range []alert.State{alert.Resolved, alert.FalsePositive} {
		if !alert.Explains(ending, alert.Open) {
			t.Errorf("reopening a %s alert needs no reason", ending)
		}
	}
}

func TestEveryStateCrossesTheWireAndComesBackTheSame(t *testing.T) {
	seen := map[alertv1.State]alert.State{}
	for _, state := range alert.States() {
		carried := state.Wire()
		if carried == alertv1.State_STATE_UNSPECIFIED {
			t.Errorf("%s crosses the wire unspecified", state)
		}
		if earlier, taken := seen[carried]; taken {
			t.Errorf("%s and %s both cross as %s", earlier, state, carried)
		}
		seen[carried] = state

		back, known := alert.FromWire(carried)
		if !known || back != state {
			t.Errorf("%s came back as %q (known: %v)", state, back, known)
		}
	}

	if _, known := alert.FromWire(alertv1.State_STATE_UNSPECIFIED); known {
		t.Error("an unspecified state was read as a state")
	}
}

func TestARefusalNamesWhereTheAlertCanActuallyGo(t *testing.T) {
	err := alert.Illegal(alert.InInvestigation, alert.Acknowledged)
	if err == nil {
		t.Fatal("an illegal move was not refused")
	}
	for _, expected := range []string{"in_investigation", "acknowledged", "resolved", "false_positive"} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("the refusal %q does not name %s", err, expected)
		}
	}

	if err := alert.Illegal(alert.Open, alert.Open); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("moving to the state it is in was refused with %v", err)
	}
	if err := alert.Illegal(alert.Open, "escalated"); err == nil || !strings.Contains(err.Error(), "names no alert state") {
		t.Errorf("an invented state was refused with %v", err)
	}
}
