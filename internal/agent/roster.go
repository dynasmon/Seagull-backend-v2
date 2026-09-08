package agent

import (
	"fmt"
	"sync"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Which identities the platform still honours. It is the whole of what a
// data-plane process keeps about the registry: one entry per agent the log has
// named, holding the last state decided about it and the revision that was
// decided at.
//
// Nothing is ever evicted to make room. Evicting a refusal would re-admit a
// revoked agent, so the ceiling here is how many agents an estate has
// registered — a number the platform chooses, not one a caller can drive.
type Roster struct {
	mu    sync.RWMutex
	known map[string]decided
}

type decided struct {
	admits   bool
	revision uint64
}

func NewRoster() *Roster { return &Roster{known: map[string]decided{}} }

// A record older than the one already applied is stepped over, so two control
// planes publishing about the same agent at once cannot leave the gateway
// holding the earlier answer for ever. Two of them deciding one revision
// differently leave it holding neither: the platform cannot say which decision
// it made, and an agent it cannot decide about is one it stops admitting.
func (r *Roster) Apply(record *agentv1.Admission) error {
	if record.GetAgentId() == "" {
		return fmt.Errorf("%w: the admission record names no agent", ErrMalformed)
	}
	state, known := FromWire(record.GetState())
	if !known {
		return fmt.Errorf("%w: %s names no agent state this build knows", ErrMalformed, record.GetState())
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	held, seen := r.known[record.GetAgentId()]
	switch {
	case seen && record.GetRevision() < held.revision:
		return nil
	case seen && record.GetRevision() == held.revision && held.admits != state.Admits():
		r.known[record.GetAgentId()] = decided{revision: held.revision}
		return fmt.Errorf("%w: revision %d of agent %q decides both ways",
			ErrConflict, record.GetRevision(), record.GetAgentId())
	}
	r.known[record.GetAgentId()] = decided{admits: state.Admits(), revision: record.GetRevision()}
	return nil
}

// What the platform holds about an agent whose record it could not read. The log
// is compacted and keyed by the agent, so that record is the whole of what was
// decided about it: forgetting it would re-admit a certificate somebody revoked,
// and the only safe reading of a decision nothing can read is that the agent is
// no longer admitted. The revision is kept so a later record still replaces it.
func (r *Roster) Refuse(agentID string) {
	if agentID == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	held := r.known[agentID]
	held.admits = false
	r.known[agentID] = held
}

// An agent the registry has never named is admitted: identity comes from the
// certificate, and this answers only whether the platform has stopped honouring
// one.
func (r *Roster) Admits(agentID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	held, seen := r.known[agentID]
	return !seen || held.admits
}

func (r *Roster) Known() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.known)
}

func (r *Roster) Refused() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	refused := 0
	for _, held := range r.known {
		if !held.admits {
			refused++
		}
	}
	return refused
}
