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

func (r Report) Liveness(now time.Time) agentv1.Liveness {
	if r.Status == nil {
		return agentv1.Liveness_LIVENESS_UNSPECIFIED
	}
	return Heard{
		Received: r.Received,
		Interval: r.Status.GetInterval().AsDuration(),
		Stopping: r.Status.GetCondition() == agentv1.Status_CONDITION_STOPPED,
	}.Liveness(now)
}

// What liveness is judged from, which is all a reader of the whole fleet needs
// of each agent's newest report: when it arrived, the interval it announced,
// and whether it said the agent was stopping.
type Heard struct {
	Received time.Time
	Interval time.Duration
	Stopping bool
}

// Judged at the moment it is read, against the interval the report announced,
// so a report that was on time an hour ago is not still on time now. An agent
// that said it was stopping stays stopped however long ago that was, because
// that is the last thing it said; silence is a fact about the reports and
// decides nothing about the agent.
func (h Heard) Liveness(now time.Time) agentv1.Liveness {
	if h.Received.IsZero() {
		return agentv1.Liveness_LIVENESS_UNSPECIFIED
	}
	if h.Stopping {
		return agentv1.Liveness_LIVENESS_STOPPED
	}
	every := min(max(h.Interval, MinInterval), MaxInterval)
	switch late := now.Sub(h.Received); {
	case late <= Allowance*every:
		return agentv1.Liveness_LIVENESS_ACTIVE
	case late <= Silence*every:
		return agentv1.Liveness_LIVENESS_LATE
	}
	return agentv1.Liveness_LIVENESS_SILENT
}
