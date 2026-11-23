package fleetjudge

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// A finding of refusals observed again is decided again once this has passed
// since its previous decision, so a holder of a key asking without pause costs
// a decision a minute.
const refusalsAgain = time.Minute

// The open finding a gateway's refusals made while one certificate is in force,
// at most one per agent: binding another certificate closes it. counted is the
// newest refusal its decisions already held when the judge started, so reading
// the refusals back counts only what came after.
type refusing struct {
	finding  *agentv1.Finding
	counted  time.Time
	observed bool
}

func (j *Judge) replayedRefusals(ctx context.Context, records []Record) error {
	return j.refuse(ctx, records, false)
}

func (j *Judge) heardRefusals(ctx context.Context, records []Record) error {
	return j.refuse(ctx, records, true)
}

// A refusal is evidence only of the certificate in force and the admission it
// was refused under: one under a certificate since replaced, or from before the
// admission in force was decided, belongs to an episode that already ended.
func (j *Judge) refuse(_ context.Context, records []Record, live bool) error {
	now := j.now()
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, record := range records {
		var refused agentv1.Refusal
		if err := proto.Unmarshal(record.Value, &refused); err != nil || agentfinding.ValidateRefusal(&refused) != nil ||
			refused.GetAgentId() != string(record.Key) {
			j.metrics.refused.WithLabelValues("refusals").Inc()
			continue
		}
		agentID, last := refused.GetAgentId(), refused.GetLastRefusedAt().AsTime()
		known, seen := j.admitted[agentID]
		if !seen || !known.admits || known.inForce != refused.GetFingerprintSha256() || last.Before(known.changed) {
			j.metrics.refusals.WithLabelValues("outdated").Add(float64(refused.GetRefusals()))
			continue
		}
		open := j.refusing[agentID]
		switch {
		case open == nil:
			opened := &refusing{finding: agentfinding.Refusing(known.tenant, agentID, &refused, now)}
			j.refusing[agentID] = opened
			j.decide(opened.finding)
		case !live && !last.After(open.counted):
			continue
		default:
			open.finding = agentfinding.RefusedAgain(open.finding, &refused)
			open.observed = true
		}
		j.metrics.refusals.WithLabelValues("counted").Add(float64(refused.GetRefusals()))
	}
	return nil
}

// The certificate in force changed or the agent is no longer admitted: the
// episode the refusals were evidence of is over, at the instant the registry
// decided so.
func (j *Judge) ended(agentID string, now time.Time) {
	open := j.refusing[agentID]
	if open == nil {
		return
	}
	known := j.admitted[agentID]
	switch {
	case !known.admits:
		j.decide(agentfinding.Closed(open.finding, agentv1.Finding_CLOSURE_NOT_ADMITTED, whenever(known.changed, now), now))
	case known.inForce != "" && agentfinding.RefusingID(known.tenant, agentID, known.inForce) != open.finding.GetFindingId():
		j.decide(agentfinding.Closed(open.finding, agentv1.Finding_CLOSURE_REBOUND, whenever(known.changed, now), now))
	default:
		return
	}
	delete(j.refusing, agentID)
}

func (j *Judge) restoreRefusals(recalled *agentv1.Finding, now time.Time) {
	if recalled.GetState() != agentv1.Finding_STATE_OPEN {
		return
	}
	agentID := recalled.GetAgentId()
	j.refusing[agentID] = &refusing{finding: recalled, counted: recalled.GetLastObservedAt().AsTime()}
	j.ended(agentID, now)
}

func (j *Judge) settleRefusals(now time.Time) {
	for _, open := range j.refusing {
		since := now.Sub(open.finding.GetDecidedAt().AsTime())
		if (open.observed && since >= refusalsAgain) || since >= j.again {
			open.finding = agentfinding.Again(open.finding, now)
			open.observed = false
			j.decide(open.finding)
		}
	}
}
