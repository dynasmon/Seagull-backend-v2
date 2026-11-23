package agentfinding

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const (
	fingerprintLength = 64
	gatewayEpisode    = "gateway"
)

// A gateway's refusal is read only when it names an agent, its tenant, the
// admission it was refused under and the route, and dates what it gathers: a
// finding is named from those, and one named from less would be nobody's.
func ValidateRefusal(refused *agentv1.Refusal) error {
	switch {
	case refused == nil:
		return &event.Violation{Field: "refusal", Reason: "is missing"}
	case refused.GetSchemaVersion() != agentidentity.RefusalSchemaVersion:
		return &event.Violation{Field: "schema_version", Reason: fmt.Sprintf("must be %d", agentidentity.RefusalSchemaVersion)}
	case refused.GetReason() != agentv1.Refusal_REASON_REPLACED_CERTIFICATE:
		return &event.Violation{Field: "reason", Reason: "is not a reason this build judges"}
	case !agentidentity.Valid(refused.GetAgentId()):
		return &event.Violation{Field: "agent_id", Reason: "is missing or malformed"}
	case !event.ValidIdentifier(refused.GetTenantId()):
		return &event.Violation{Field: "tenant_id", Reason: "is missing or malformed"}
	case len(refused.GetFingerprintSha256()) != fingerprintLength || !lowercaseHex(refused.GetFingerprintSha256()):
		return &event.Violation{Field: "fingerprint_sha256", Reason: "is not a lowercase SHA-256 fingerprint"}
	case refused.GetRevision() == 0:
		return &event.Violation{Field: "revision", Reason: "is zero, and an admission is written from revision 1"}
	case refused.GetUse().GetListener() != agentv1.Finding_Use_LISTENER_GATEWAY:
		return &event.Violation{Field: "use.listener", Reason: "is not the gateway"}
	case refused.GetRefusals() == 0:
		return &event.Violation{Field: "refusals", Reason: "is zero, and a record gathers at least one"}
	}
	if err := text("use.route", refused.GetUse().GetRoute(), MaxRouteLength, true); err != nil {
		return err
	}
	if err := text("gateway", refused.GetGateway(), event.MaxGatewayLength, true); err != nil {
		return err
	}
	if err := instant("first_refused_at", refused.GetFirstRefusedAt(), true); err != nil {
		return err
	}
	if err := instant("last_refused_at", refused.GetLastRefusedAt(), true); err != nil {
		return err
	}
	if refused.GetLastRefusedAt().AsTime().Before(refused.GetFirstRefusedAt().AsTime()) {
		return &event.Violation{Field: "last_refused_at", Reason: "is before the first refusal it gathers"}
	}
	return nil
}

// The refusals of one gateway listener while one certificate is in force are
// one finding, named by that certificate and the listener: the control
// listener's episode about the same certificate is a finding of its own, since
// each is decided by the process that saw it.
func Refusing(tenantID, agentID string, refused *agentv1.Refusal, decided time.Time) *agentv1.Finding {
	use, _ := proto.Clone(refused.GetUse()).(*agentv1.Finding_Use)
	return &agentv1.Finding{
		SchemaVersion:  SchemaVersion,
		FindingId:      RefusingID(tenantID, agentID, refused.GetFingerprintSha256()),
		TenantId:       tenantID,
		AgentId:        agentID,
		Kind:           agentv1.Finding_KIND_REPLACED_CERTIFICATE,
		State:          agentv1.Finding_STATE_OPEN,
		OpenedAt:       timestamppb.New(refused.GetFirstRefusedAt().AsTime()),
		LastObservedAt: timestamppb.New(refused.GetLastRefusedAt().AsTime()),
		Observations:   refused.GetRefusals(),
		DecidedAt:      timestamppb.New(decided.UTC()),
		Use:            use,
	}
}

// Another record of refusals under the same certificate in force, as a gateway
// published it, possibly after one it refused later.
func RefusedAgain(open *agentv1.Finding, refused *agentv1.Refusal) *agentv1.Finding {
	observed, _ := proto.Clone(open).(*agentv1.Finding)
	observed.Observations += refused.GetRefusals()
	if first := refused.GetFirstRefusedAt().AsTime(); first.Before(observed.GetOpenedAt().AsTime()) {
		observed.OpenedAt = timestamppb.New(first)
	}
	if last := refused.GetLastRefusedAt().AsTime(); last.After(observed.GetLastObservedAt().AsTime()) {
		observed.LastObservedAt = timestamppb.New(last)
		observed.Use, _ = proto.Clone(refused.GetUse()).(*agentv1.Finding_Use)
	}
	return observed
}

// The name of the finding a gateway's refusals make while inForce is the
// certificate in force, which judging them again names the same way.
func RefusingID(tenantID, agentID, inForce string) string {
	return ID(tenantID, agentID, agentv1.Finding_KIND_REPLACED_CERTIFICATE, inForce, gatewayEpisode)
}
