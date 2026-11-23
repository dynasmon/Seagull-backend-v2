package agentidentity_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func TestARefusalNamesTheCertificateInForceAndNeverTheOnePresented(t *testing.T) {
	got := agentidentity.Refused("web-01", "acme", agentidentity.Held{Binding: bound(), Revision: 7}, "POST /v1/events", "gateway-a", replacedAt)
	want := &agentv1.Refusal{
		SchemaVersion: 1, Reason: agentv1.Refusal_REASON_REPLACED_CERTIFICATE,
		TenantId: "acme", AgentId: "web-01", Revision: 7, FingerprintSha256: inForce,
		Use:            &agentv1.Finding_Use{Listener: agentv1.Finding_Use_LISTENER_GATEWAY, Route: "POST /v1/events"},
		FirstRefusedAt: timestamppb.New(replacedAt), LastRefusedAt: timestamppb.New(replacedAt), Refusals: 1, Gateway: "gateway-a",
	}
	if !proto.Equal(got, want) {
		t.Fatalf("the refusal was recorded as %v, want %v", got, want)
	}
}
