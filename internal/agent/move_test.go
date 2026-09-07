package agent_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

var moved = registered.Add(time.Hour)

func pending(t *testing.T) *agentv1.Agent {
	t.Helper()
	held, _, err := agent.Register(registration(), "operator@acme", registered)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return held
}

func active(t *testing.T) *agentv1.Agent {
	t.Helper()
	held, _, err := agent.Apply(pending(t), agent.Move{Identity: identity(), Actor: "ca@acme", At: moved})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	return held
}

func TestBindingAnIdentityIsWhatMakesAPendingAgentActive(t *testing.T) {
	held, trail, err := agent.Apply(pending(t), agent.Move{Identity: identity(), Actor: "ca@acme", At: moved})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := agent.FromWire(held.GetState()); got != agent.Active {
		t.Fatalf("a bound agent is %s", got)
	}
	if held.GetIdentity().GetFingerprintSha256() != identity().GetFingerprintSha256() {
		t.Error("the certificate identity was not recorded")
	}
	if held.GetRevision() != 2 || trail.GetFrom() != agent.Pending.Wire() || trail.GetTo() != agent.Active.Wire() {
		t.Errorf("the trail does not record the binding: %v", trail)
	}
	if agent.Legal(agent.Pending, agent.Active) {
		t.Error("becoming active was made a transition rather than a consequence of binding")
	}
}

func TestRebindingReplacesTheIdentityWithoutMovingTheAgent(t *testing.T) {
	renewed := identity()
	renewed.Serial = "9c4e1a2b3d5f6071"
	renewed.ExpiresAt = identity().GetExpiresAt()

	held, _, err := agent.Apply(active(t), agent.Move{Identity: renewed, Actor: "ca@acme", At: moved})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := agent.FromWire(held.GetState()); got != agent.Active {
		t.Fatalf("a renewed agent is %s", got)
	}
	if held.GetIdentity().GetSerial() != renewed.GetSerial() {
		t.Error("the renewed certificate was not recorded")
	}
}

func TestAnEndedAgentTakesNoFurtherIdentity(t *testing.T) {
	revoked, _, err := agent.Apply(active(t), agent.Move{
		To: agent.Revoked, Note: "the host was rebuilt", Actor: "operator@acme", At: moved,
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, _, err = agent.Apply(revoked, agent.Move{Identity: identity(), Actor: "ca@acme", At: moved})
	if !errors.Is(err, agent.ErrMalformedIdentity) {
		t.Fatalf("a revoked agent was given a new certificate: %v", err)
	}
}

func TestEveryLifecycleChangeSaysWhy(t *testing.T) {
	_, _, err := agent.Apply(active(t), agent.Move{To: agent.Disabled, Actor: "operator@acme", At: moved})
	if !errors.Is(err, agent.ErrNeedsReason) {
		t.Fatalf("an agent was disabled without a reason: %v", err)
	}
	if _, _, err := agent.Apply(active(t), agent.Move{To: agent.Disabled, Note: "noisy", At: moved}); !errors.Is(err, agent.ErrNoActor) {
		t.Fatalf("an agent was disabled by nobody: %v", err)
	}
	if _, _, err := agent.Apply(active(t), agent.Move{Actor: "operator@acme", At: moved}); !errors.Is(err, agent.ErrNothingAsked) {
		t.Fatalf("an empty move was applied: %v", err)
	}
}

func TestAnAgentThatMovedIsNotOverwrittenBySomebodyActingOnWhatItWas(t *testing.T) {
	held := active(t)
	_, _, err := agent.Apply(held, agent.Move{
		To: agent.Disabled, Note: "noisy", Actor: "operator@acme", At: moved, Expected: held.GetRevision() - 1,
	})
	if !errors.Is(err, agent.ErrMoved) {
		t.Fatalf("a stale revision was applied: %v", err)
	}
	if _, _, err := agent.Apply(held, agent.Move{
		To: agent.Disabled, Note: "noisy", Actor: "operator@acme", At: moved, Expected: held.GetRevision(),
	}); err != nil {
		t.Fatalf("the current revision was refused: %v", err)
	}
}

func TestAnIllegalMoveIsRefusedAndSaysWhereTheAgentCanGo(t *testing.T) {
	_, _, err := agent.Apply(pending(t), agent.Move{
		To: agent.Active, Note: "it is fine", Actor: "operator@acme", At: moved,
	})
	if !errors.Is(err, agent.ErrIllegalMove) {
		t.Fatalf("a pending agent was declared active: %v", err)
	}
	_, _, invented := agent.Apply(active(t), agent.Move{
		To: "retired", Note: "gone", Actor: "operator@acme", At: moved,
	})
	if !errors.Is(invented, agent.ErrUnknownState) {
		t.Fatalf("an invented state was applied: %v", invented)
	}
	if !agent.Refused(err) || !agent.Refused(invented) {
		t.Error("a caller's mistake was not reported as one")
	}
}

func TestWhatTheDataPlaneIsToldIsLessThanWhatWasDecided(t *testing.T) {
	held, _, err := agent.Apply(active(t), agent.Move{
		To: agent.Revoked, Note: "the key leaked", Actor: "operator@acme", At: moved,
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	told := agent.Admission(held)
	if told.GetAgentId() != held.GetAgentId() || told.GetTenantId() != held.GetTenantId() {
		t.Fatalf("the admission record does not name the agent: %v", told)
	}
	if told.GetState() != held.GetState() || told.GetRevision() != held.GetRevision() {
		t.Fatalf("the admission record does not carry what was decided: %v", told)
	}

	fields := told.ProtoReflect().Descriptor().Fields()
	for index := range fields.Len() {
		switch name := string(fields.Get(index).Name()); name {
		case "agent_id", "tenant_id", "state", "revision", "changed_at":
		default:
			t.Errorf("the data plane is told %q about an agent", name)
		}
	}
}
