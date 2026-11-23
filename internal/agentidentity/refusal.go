package agentidentity

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const RefusalSchemaVersion = 1

// What a gateway says of refusing a certificate a renewal had replaced: the
// certificate in force, by its fingerprint, and never the one presented.
func Refused(agentID, tenant string, held Held, route, gateway string, at time.Time) *agentv1.Refusal {
	return &agentv1.Refusal{
		SchemaVersion:     RefusalSchemaVersion,
		Reason:            agentv1.Refusal_REASON_REPLACED_CERTIFICATE,
		TenantId:          tenant,
		AgentId:           agentID,
		Revision:          held.Revision,
		FingerprintSha256: held.Binding.Fingerprint,
		Use:               &agentv1.Finding_Use{Listener: agentv1.Finding_Use_LISTENER_GATEWAY, Route: route},
		FirstRefusedAt:    timestamppb.New(at.UTC()),
		LastRefusedAt:     timestamppb.New(at.UTC()),
		Refusals:          1,
		Gateway:           gateway,
	}
}
