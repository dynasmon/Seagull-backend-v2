package agent_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func TestAnAgentIsRetiredForwardsAndAnEndingHasNoWayBack(t *testing.T) {
	legal := map[agent.State][]agent.State{
		agent.Pending:  {agent.Disabled, agent.Revoked, agent.Decommissioned},
		agent.Active:   {agent.Disabled, agent.Revoked, agent.Decommissioned},
		agent.Disabled: {agent.Active, agent.Revoked, agent.Decommissioned},
	}

	for _, from := range agent.States() {
		for _, to := range agent.States() {
			want := slices.Contains(legal[from], to)
			if got := agent.Legal(from, to); got != want {
				t.Errorf("%s -> %s is %v and should be %v", from, to, got, want)
			}
		}
		if slices.Contains(agent.Reachable(from), from) {
			t.Errorf("%s reaches itself", from)
		}
	}
}

func TestARevokedIdentifierIsNeverAdmittedAgain(t *testing.T) {
	for _, ending := range []agent.State{agent.Revoked, agent.Decommissioned} {
		if !ending.Final() {
			t.Errorf("%s does not report itself final", ending)
		}
		if reachable := agent.Reachable(ending); len(reachable) != 0 {
			t.Errorf("an agent that is %s becomes %v", ending, reachable)
		}
		if ending.Admits() {
			t.Errorf("an agent that is %s still admits telemetry", ending)
		}
	}
	if agent.Legal(agent.Revoked, agent.Pending) {
		t.Error("a revoked agent was re-enrolled under the identifier the gateway knows it by")
	}
}

func TestRegisteringAnAgentTakesNothingAwayFromIt(t *testing.T) {
	if !agent.Pending.Admits() {
		t.Error("registering an agent stopped it sending before anybody decided anything about it")
	}
	if !agent.Active.Admits() {
		t.Error("an active agent is not admitted")
	}
	if agent.Disabled.Admits() {
		t.Error("a disabled agent is still admitted")
	}
}

func TestAnUndeclaredStateIsRefusedRatherThanCarried(t *testing.T) {
	if agent.State("retired").Valid() {
		t.Fatal("an invented state reports itself valid")
	}
	err := agent.Illegal(agent.Active, "retired")
	if err == nil || !strings.Contains(err.Error(), "names no agent state") {
		t.Fatalf("an invented state was not refused as one: %v", err)
	}
	if _, known := agent.FromWire(agentv1.State_STATE_UNSPECIFIED); known {
		t.Error("an unspecified wire state was read as a state")
	}
}

func TestEveryStateCrossesTheWireInBothDirections(t *testing.T) {
	for _, state := range agent.States() {
		back, known := agent.FromWire(state.Wire())
		if !known || back != state {
			t.Errorf("%s came back as %q (known %v)", state, back, known)
		}
		if state.Wire() == agentv1.State_STATE_UNSPECIFIED {
			t.Errorf("%s has no wire value", state)
		}
	}
}
