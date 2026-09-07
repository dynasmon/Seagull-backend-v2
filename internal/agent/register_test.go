package agent_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

var registered = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

func registration() *agentv1.Registration {
	return &agentv1.Registration{
		AgentId:      "web-01",
		TenantId:     "acme",
		Platform:     &agentv1.Platform{Os: "linux", Architecture: "amd64", Hostname: "web-01.acme.internal"},
		AgentVersion: "2.0.0",
		Note:         "first sensor in the estate",
	}
}

func TestARegisteredAgentIsPendingUntilSomethingIsBoundToIt(t *testing.T) {
	held, trail, err := agent.Register(registration(), "operator@acme", registered)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := agent.FromWire(held.GetState()); got != agent.Pending {
		t.Fatalf("a registered agent is %s", got)
	}
	if held.GetIdentity() != nil {
		t.Error("a registered agent already carries a certificate identity")
	}
	if held.GetRevision() != 1 || held.GetSchemaVersion() != agent.SchemaVersion {
		t.Errorf("registered at revision %d, schema %d", held.GetRevision(), held.GetSchemaVersion())
	}
	if held.GetRegisteredAt().AsTime() != registered || held.GetChangedBy() != "operator@acme" {
		t.Errorf("registered at %s by %q", held.GetRegisteredAt().AsTime(), held.GetChangedBy())
	}
	if trail.GetRevision() != 1 || trail.GetTo() != held.GetState() || trail.GetActor() != "operator@acme" {
		t.Errorf("the trail does not record the registration: %v", trail)
	}
	if trail.GetNote() != "first sensor in the estate" {
		t.Errorf("the reason was not kept: %q", trail.GetNote())
	}
}

func TestAnAgentIsRegisteredUnderAnIdentifierAGatewayCanRead(t *testing.T) {
	for name, identifier := range map[string]string{
		"empty":     "",
		"traversal": "../../etc/passwd",
		"spaces":    "web 01",
		"slashes":   "tenant/web-01",
		"too long":  strings.Repeat("a", 70),
	} {
		t.Run(name, func(t *testing.T) {
			asked := registration()
			asked.AgentId = identifier
			if _, _, err := agent.Register(asked, "operator@acme", registered); !errors.Is(err, agent.ErrMalformed) {
				t.Fatalf("expected a malformed registration, got %v", err)
			}
		})
	}
}

func TestAnAgentBelongsToATenantAndIsRegisteredBySomebody(t *testing.T) {
	without := registration()
	without.TenantId = ""
	if _, _, err := agent.Register(without, "operator@acme", registered); !errors.Is(err, agent.ErrMalformed) {
		t.Fatalf("an agent was registered into no tenant: %v", err)
	}

	malformed := registration()
	malformed.TenantId = "acme corp"
	if _, _, err := agent.Register(malformed, "operator@acme", registered); !errors.Is(err, agent.ErrMalformed) {
		t.Fatalf("an unusable tenant identifier was accepted: %v", err)
	}

	if _, _, err := agent.Register(registration(), "", registered); !errors.Is(err, agent.ErrNoActor) {
		t.Fatalf("an agent was registered by nobody: %v", err)
	}
}

func TestWhatAMachineSaysItIsIsBounded(t *testing.T) {
	cases := map[string]func(*agentv1.Registration){
		"operating system": func(r *agentv1.Registration) { r.Platform.Os = strings.Repeat("l", 200) },
		"architecture":     func(r *agentv1.Registration) { r.Platform.Architecture = strings.Repeat("x", 40) },
		"hostname":         func(r *agentv1.Registration) { r.Platform.Hostname = strings.Repeat("h", 300) },
		"version":          func(r *agentv1.Registration) { r.AgentVersion = strings.Repeat("9", 100) },
		"note":             func(r *agentv1.Registration) { r.Note = strings.Repeat("n", 600) },
	}
	for name, oversize := range cases {
		t.Run(name, func(t *testing.T) {
			asked := registration()
			oversize(asked)
			if _, _, err := agent.Register(asked, "operator@acme", registered); !errors.Is(err, agent.ErrMalformed) {
				t.Fatalf("an unbounded %s was accepted: %v", name, err)
			}
		})
	}
}
