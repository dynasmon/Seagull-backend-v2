package agentfinding

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// One episode of certificates a renewal had replaced being used again, as the
// registry keeps it beside the certificate trail. It is named by the certificate
// in force when the first use was refused, which the finding it becomes never
// carries: a digest of it names the finding, and nothing else leaves the
// platform. Revision counts the decisions about it, each published once; Route
// is the route of the agent listener it was last refused on, empty for renewal.
type Replaced struct {
	TenantID       string
	AgentID        string
	InForce        string
	Route          string
	OpenedAt       time.Time
	LastObservedAt time.Time
	Observations   uint64
	Closure        agentv1.Finding_Closure
	ClosedAt       time.Time
	DecidedAt      time.Time
	Revision       uint64
}

func (r Replaced) Finding(use *agentv1.Finding_Use) *agentv1.Finding {
	decided := &agentv1.Finding{
		SchemaVersion:  SchemaVersion,
		FindingId:      ID(r.TenantID, r.AgentID, agentv1.Finding_KIND_REPLACED_CERTIFICATE, r.InForce),
		TenantId:       r.TenantID,
		AgentId:        r.AgentID,
		Kind:           agentv1.Finding_KIND_REPLACED_CERTIFICATE,
		State:          agentv1.Finding_STATE_OPEN,
		OpenedAt:       timestamppb.New(r.OpenedAt.UTC()),
		LastObservedAt: timestamppb.New(later(r.LastObservedAt.UTC(), r.OpenedAt.UTC())),
		Observations:   r.Observations,
		DecidedAt:      timestamppb.New(r.DecidedAt.UTC()),
		Use:            proto.Clone(use).(*agentv1.Finding_Use),
	}
	if r.Closure != agentv1.Finding_CLOSURE_UNSPECIFIED {
		decided.State = agentv1.Finding_STATE_CLOSED
		decided.Closure = r.Closure
		decided.ClosedAt = timestamppb.New(later(r.ClosedAt.UTC(), r.OpenedAt.UTC()))
	}
	return decided
}

func Ends(before, after *agentv1.Agent) agentv1.Finding_Closure {
	if state, known := agent.FromWire(after.GetState()); !known || !state.Admits() {
		return agentv1.Finding_CLOSURE_NOT_ADMITTED
	}
	if after.GetIdentity().GetFingerprintSha256() != before.GetIdentity().GetFingerprintSha256() {
		return agentv1.Finding_CLOSURE_REBOUND
	}
	return agentv1.Finding_CLOSURE_UNSPECIFIED
}
