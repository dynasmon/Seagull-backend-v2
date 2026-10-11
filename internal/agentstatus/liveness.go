package agentstatus

import (
	"time"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// The newest report the platform holds of one agent, and when it arrived by
// the platform's own clock. The arrival is what liveness is measured from: an
// agent cannot report itself alive by writing a later `reported_at`.
type Report struct {
	Received time.Time
	Status   *agentv1.Status
}

// Judged at the moment it is read, against the interval the report announced,
// so a report that was on time an hour ago is not still on time now. An agent
// that said it was stopping stays stopped however long ago that was, because
// that is the last thing it said; silence is a fact about the reports and
// decides nothing about the agent.
func (r Report) Liveness(now time.Time) agentv1.Liveness {
	if r.Status == nil || r.Received.IsZero() {
		return agentv1.Liveness_LIVENESS_UNSPECIFIED
	}
	if r.Status.GetCondition() == agentv1.Status_CONDITION_STOPPED {
		return agentv1.Liveness_LIVENESS_STOPPED
	}
	every := min(max(r.Status.GetInterval().AsDuration(), MinInterval), MaxInterval)
	switch late := now.Sub(r.Received); {
	case late <= Allowance*every:
		return agentv1.Liveness_LIVENESS_ACTIVE
	case late <= Silence*every:
		return agentv1.Liveness_LIVENESS_LATE
	}
	return agentv1.Liveness_LIVENESS_SILENT
}
