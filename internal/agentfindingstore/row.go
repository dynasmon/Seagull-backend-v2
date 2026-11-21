package agentfindingstore

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// One decision about a finding, as the newest the store holds of it: the columns
// a reader asks about, and the decision itself, byte for byte as it was
// published, which is what a reader is handed back. A zero closed_at is a finding
// that is still open.
type Row struct {
	TenantID  string
	AgentID   string
	FindingID string

	Kind    string
	State   string
	Closure string

	OpenedAt       time.Time
	LastObservedAt time.Time
	Observations   uint64
	ClosedAt       time.Time
	DecidedAt      time.Time

	Finding []byte
}

func Project(decided *agentv1.Finding, published []byte) Row {
	return Row{
		TenantID:  decided.GetTenantId(),
		AgentID:   decided.GetAgentId(),
		FindingID: decided.GetFindingId(),

		Kind:    agentfinding.KindName(decided.GetKind()),
		State:   agentfinding.StateName(decided.GetState()),
		Closure: agentfinding.ClosureName(decided.GetClosure()),

		OpenedAt:       instant(decided.GetOpenedAt()),
		LastObservedAt: instant(decided.GetLastObservedAt()),
		Observations:   decided.GetObservations(),
		ClosedAt:       instant(decided.GetClosedAt()),
		DecidedAt:      instant(decided.GetDecidedAt()),

		Finding: published,
	}
}

func instant(stamp *timestamppb.Timestamp) time.Time {
	if stamp == nil {
		return time.Time{}
	}
	return stamp.AsTime().UTC()
}
