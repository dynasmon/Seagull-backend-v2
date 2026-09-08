package agent_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func admission(agentID string, state agent.State, revision uint64) *agentv1.Admission {
	return &agentv1.Admission{AgentId: agentID, TenantId: "acme", State: state.Wire(), Revision: revision}
}

func TestAnAgentTheRosterHasNeverHeardOfIsAdmitted(t *testing.T) {
	roster := agent.NewRoster()
	if !roster.Admits("web-01") {
		t.Fatal("an unregistered agent was refused by a roster that knows nothing about it")
	}
	if roster.Refused() != 0 {
		t.Fatalf("an empty roster refuses %d agents", roster.Refused())
	}
}

func TestOnlyTheStatesThatStopAnAgentAreKept(t *testing.T) {
	roster := agent.NewRoster()
	for _, state := range []agent.State{agent.Pending, agent.Active} {
		if err := roster.Apply(admission("web-01", state, 1)); err != nil {
			t.Fatalf("apply %s: %v", state, err)
		}
		if !roster.Admits("web-01") || roster.Refused() != 0 {
			t.Fatalf("a %s agent was refused", state)
		}
	}
	for _, state := range []agent.State{agent.Disabled, agent.Revoked, agent.Decommissioned} {
		if err := roster.Apply(admission("web-01", state, 2)); err != nil {
			t.Fatalf("apply %s: %v", state, err)
		}
		if roster.Admits("web-01") || roster.Refused() != 1 {
			t.Fatalf("a %s agent was admitted", state)
		}
	}
}

func TestAnAgentLetInAgainStopsBeingRefused(t *testing.T) {
	roster := agent.NewRoster()
	if err := roster.Apply(admission("web-01", agent.Disabled, 2)); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := roster.Apply(admission("web-01", agent.Active, 3)); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !roster.Admits("web-01") || roster.Refused() != 0 {
		t.Fatal("a re-enabled agent is still refused")
	}
}

func TestAReplayedRecordDoesNotBringARefusalBack(t *testing.T) {
	roster := agent.NewRoster()
	for _, record := range []*agentv1.Admission{
		admission("web-01", agent.Disabled, 2),
		admission("web-01", agent.Active, 3),
		admission("web-01", agent.Disabled, 2),
	} {
		if err := roster.Apply(record); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
	if !roster.Admits("web-01") {
		t.Fatal("an older record was applied over a newer one")
	}
}

func TestARecordTheRosterCannotReadIsRefusedRatherThanApplied(t *testing.T) {
	roster := agent.NewRoster()
	if err := roster.Apply(&agentv1.Admission{State: agent.Revoked.Wire()}); !errors.Is(err, agent.ErrMalformed) {
		t.Fatalf("a record naming no agent was applied: %v", err)
	}
	if err := roster.Apply(&agentv1.Admission{AgentId: "web-01"}); !errors.Is(err, agent.ErrMalformed) {
		t.Fatalf("a record in no state was applied: %v", err)
	}
	if roster.Refused() != 0 {
		t.Fatal("an unreadable record changed what the roster refuses")
	}
}

func TestTheRosterIsReadWhileItIsWritten(t *testing.T) {
	roster := agent.NewRoster()
	var waiting sync.WaitGroup
	for worker := range 8 {
		waiting.Add(2)
		go func() {
			defer waiting.Done()
			for revision := range 100 {
				_ = roster.Apply(admission("web-01", agent.Disabled, uint64(revision)))
				_ = roster.Apply(admission("db-07", agent.Active, uint64(revision)))
			}
		}()
		go func() {
			defer waiting.Done()
			for range 100 {
				roster.Admits("web-01")
				roster.Admits("db-0" + string(rune('0'+worker)))
			}
		}()
	}
	waiting.Wait()

	if roster.Admits("web-01") {
		t.Fatal("a disabled agent is admitted after concurrent use")
	}
}

// The log is compacted and keyed by the agent, so the record a reader could not
// read is the whole of what the platform decided about it. Forgetting it would
// re-admit the certificate the record revoked.
func TestAnAgentWhoseRecordCouldNotBeReadIsNoLongerAdmitted(t *testing.T) {
	roster := agent.NewRoster()

	roster.Refuse("web-01")
	if roster.Admits("web-01") {
		t.Error("an agent whose record could not be read is still admitted")
	}
	if roster.Known() != 1 || roster.Refused() != 1 {
		t.Errorf("the roster holds %d agents and refuses %d", roster.Known(), roster.Refused())
	}
	if !roster.Admits("web-02") {
		t.Error("refusing one agent refused another")
	}
}

// The revision is kept, so the control plane can still say something readable
// about the agent afterwards and be believed.
func TestAReadableRecordReplacesARefusalItFollows(t *testing.T) {
	roster := agent.NewRoster()

	if err := roster.Apply(admission("web-01", agent.Active, 3)); err != nil {
		t.Fatalf("apply an admission: %v", err)
	}
	roster.Refuse("web-01")
	if roster.Admits("web-01") {
		t.Fatal("the refusal did not take effect")
	}

	if err := roster.Apply(admission("web-01", agent.Active, 4)); err != nil {
		t.Fatalf("apply a later admission: %v", err)
	}
	if !roster.Admits("web-01") {
		t.Error("a later readable record did not replace the refusal")
	}
}

// A revocation that arrives twice at one revision is the same decision, and
// applying it again is not a disagreement.
func TestOneRevisionRepublishedUnchangedIsApplied(t *testing.T) {
	roster := agent.NewRoster()
	record := admission("web-01", agent.Revoked, 7)

	for range 2 {
		if err := roster.Apply(record); err != nil {
			t.Fatalf("republish one revocation: %v", err)
		}
	}
	if roster.Admits("web-01") {
		t.Error("republishing a revocation re-admitted the agent")
	}
}

// Two control planes deciding one revision differently leave the platform unable
// to say what it decided, and an agent it cannot decide about is one it stops
// admitting rather than one it guesses about.
func TestOneRevisionDecidedBothWaysStopsAdmittingTheAgent(t *testing.T) {
	roster := agent.NewRoster()

	if err := roster.Apply(admission("web-01", agent.Revoked, 7)); err != nil {
		t.Fatalf("apply a revocation: %v", err)
	}
	err := roster.Apply(admission("web-01", agent.Active, 7))
	if !errors.Is(err, agent.ErrConflict) {
		t.Fatalf("the conflicting record was applied: %v", err)
	}
	if roster.Admits("web-01") {
		t.Error("a conflicting revision re-admitted a revoked agent")
	}
}
