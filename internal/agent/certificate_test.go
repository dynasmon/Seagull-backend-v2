package agent_test

import (
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
)

// A renewal answers the certificate it was presented with and its request, and
// a certificate an operator had signed answers no renewal, so no renewal can be
// taken for the one that asked for it.
func TestWhatABindingAnsweredIsTheRenewalThatAskedForIt(t *testing.T) {
	presented, request := strings.Repeat("ef", 32), strings.Repeat("0a", 32)

	renewed := agent.Answering(agent.Move{Identity: identity(), PresentedFingerprint: presented, Request: request, Renewal: true})
	if renewed != (agent.Asked{Presented: presented, Request: request}) {
		t.Fatalf("a renewal answered %+v", renewed)
	}
	if issued := agent.Answering(agent.Move{Identity: identity(), PresentedFingerprint: presented, Request: request}); issued != (agent.Asked{}) {
		t.Fatalf("a certificate an operator had signed answered %+v", issued)
	}
}
