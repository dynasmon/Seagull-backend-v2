package agent_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func TestARenewalIsDecidedBeforeAnythingIsSignedAsBindingWhatItAskedForWouldBe(t *testing.T) {
	current := active(t)
	inForce := current.GetIdentity().GetFingerprintSha256()
	ended := func(to agent.State) *agentv1.Agent {
		held, _, err := agent.Apply(active(t), agent.Move{To: to, Note: "the host was rebuilt", Actor: "operator@acme", At: moved})
		if err != nil {
			t.Fatalf("move to %s: %v", to, err)
		}
		return held
	}
	replaced, answered := strings.Repeat("ef", 32), strings.Repeat("0a", 32)
	renewed := identity()
	renewed.Serial, renewed.FingerprintSha256 = "9c4e1a2b3d5f6071", strings.Repeat("cd", 32)

	for name, c := range map[string]struct {
		held *agentv1.Agent
		move agent.Move
		want error
	}{
		"the certificate in force": {current, agent.Move{PresentedFingerprint: inForce}, nil},
		"a replaced certificate":   {current, agent.Move{PresentedFingerprint: replaced}, agent.ErrCertificateReplaced},
		"a renewal asked again": {current, agent.Move{PresentedFingerprint: replaced, Request: answered,
			Bound: agent.Asked{Presented: replaced, Request: answered}}, nil},
		"a disabled agent": {ended(agent.Disabled), agent.Move{PresentedFingerprint: inForce}, agent.ErrIllegalMove},
		"a revoked agent":  {ended(agent.Revoked), agent.Move{PresentedFingerprint: inForce}, agent.ErrMalformedIdentity},
	} {
		t.Run(name, func(t *testing.T) {
			c.move.Actor, c.move.At, c.move.Renewal = "agent-001", moved, true
			asked := agent.Renewing(c.held, c.move)
			if (c.want == nil) != (asked == nil) || (c.want != nil && !errors.Is(asked, c.want)) {
				t.Fatalf("asked before signing, %s was answered %v, want %v", name, asked, c.want)
			}
			c.move.Identity = renewed
			if _, _, bound := agent.Apply(c.held, c.move); (asked == nil) != (bound == nil) || (c.want != nil && !errors.Is(bound, c.want)) {
				t.Fatalf("binding what %s asked for was answered %v, and asking before signing %v", name, bound, asked)
			}
		})
	}
}
