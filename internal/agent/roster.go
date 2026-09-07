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
// holding the earlier answer for ever.
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

	if held, seen := r.known[record.GetAgentId()]; seen && record.GetRevision() < held.revision {
		return nil
	}
	r.known[record.GetAgentId()] = decided{admits: state.Admits(), revision: record.GetRevision()}
	return nil
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
