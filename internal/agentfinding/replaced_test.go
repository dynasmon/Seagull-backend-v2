package agentfinding_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func renewalUse() *agentv1.Finding_Use {
	return &agentv1.Finding_Use{Listener: agentv1.Finding_Use_LISTENER_CONTROL, Route: "POST /v1/agents/certificate"}
}

func TestAReplacedCertificateIsNamedByTheCertificateInForceAndNeverNamesIt(t *testing.T) {
	inForce := strings.Repeat("ab", 32)
	used := agentfinding.Replaced{
		TenantID: "default", AgentID: "web-01", InForce: inForce,
		OpenedAt: opened, LastObservedAt: opened.Add(10 * time.Minute), Observations: 3, DecidedAt: opened.Add(10 * time.Minute), Revision: 3,
	}
	decided := used.Finding(renewalUse())
	if err := agentfinding.Validate(decided); err != nil {
		t.Fatalf("a replaced certificate the registry kept was refused: %v", err)
	}
	if decided.GetFindingId() != agentfinding.ID("default", "web-01", agentv1.Finding_KIND_REPLACED_CERTIFICATE, inForce) ||
		decided.GetKind() != agentv1.Finding_KIND_REPLACED_CERTIFICATE || decided.GetState() != agentv1.Finding_STATE_OPEN ||
		decided.GetObservations() != 3 || !decided.GetOpenedAt().AsTime().Equal(opened) ||
		!decided.GetLastObservedAt().AsTime().Equal(opened.Add(10*time.Minute)) || len(decided.GetReports()) != 0 ||
		!proto.Equal(decided.GetUse(), renewalUse()) {
		t.Errorf("a replaced certificate was decided as %v", decided)
	}
	encoded, err := proto.Marshal(decided)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(inForce)) {
		t.Error("the finding names the certificate in force")
	}

	used.Closure, used.ClosedAt, used.DecidedAt = agentv1.Finding_CLOSURE_REBOUND, opened.Add(time.Hour), opened.Add(time.Hour)
	ended := used.Finding(renewalUse())
	if err := agentfinding.Validate(ended); err != nil || ended.GetState() != agentv1.Finding_STATE_CLOSED ||
		ended.GetClosure() != agentv1.Finding_CLOSURE_REBOUND || !ended.GetClosedAt().AsTime().Equal(opened.Add(time.Hour)) ||
		ended.GetFindingId() != decided.GetFindingId() {
		t.Errorf("a replaced certificate another one ended was decided as %v (%v)", ended, err)
	}
	used.ClosedAt = opened.Add(-time.Hour)
	if early := used.Finding(renewalUse()); !early.GetClosedAt().AsTime().Equal(opened) {
		t.Errorf("a replaced certificate closed before it opened, at %s", early.GetClosedAt().AsTime())
	}
}

func TestAMoveEndsTheReplacedCertificateWhenItBindsAnotherOrStopsAdmitting(t *testing.T) {
	held := func(state agentv1.State, fingerprint string) *agentv1.Agent {
		return &agentv1.Agent{AgentId: "web-01", TenantId: "default", State: state, Identity: &agentv1.Identity{FingerprintSha256: fingerprint}}
	}
	first, second := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	for name, c := range map[string]struct {
		before, after *agentv1.Agent
		want          agentv1.Finding_Closure
	}{
		"a renewal":                      {held(agentv1.State_STATE_ACTIVE, first), held(agentv1.State_STATE_ACTIVE, second), agentv1.Finding_CLOSURE_REBOUND},
		"a certificate an operator gave": {held(agentv1.State_STATE_DISABLED, first), held(agentv1.State_STATE_DISABLED, second), agentv1.Finding_CLOSURE_NOT_ADMITTED},
		"disabling":                      {held(agentv1.State_STATE_ACTIVE, first), held(agentv1.State_STATE_DISABLED, first), agentv1.Finding_CLOSURE_NOT_ADMITTED},
		"revoking with another":          {held(agentv1.State_STATE_ACTIVE, first), held(agentv1.State_STATE_REVOKED, second), agentv1.Finding_CLOSURE_NOT_ADMITTED},
		"enabling":                       {held(agentv1.State_STATE_DISABLED, first), held(agentv1.State_STATE_ACTIVE, first), agentv1.Finding_CLOSURE_UNSPECIFIED},
		"nothing about it":               {held(agentv1.State_STATE_ACTIVE, first), held(agentv1.State_STATE_ACTIVE, first), agentv1.Finding_CLOSURE_UNSPECIFIED},
	} {
		if got := agentfinding.Ends(c.before, c.after); got != c.want {
			t.Errorf("%s ends a replaced certificate with %v, want %v", name, got, c.want)
		}
	}
}
