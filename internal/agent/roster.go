package agent

import (
	"fmt"
	"sync"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Which identities the platform still honours, and the tenant each one's
// telemetry belongs to. It is the whole of what a data-plane process keeps about
// the registry: one entry per agent the log has named, holding the last state
// and tenant decided about it and the revision they were decided at.
//
// Nothing is ever evicted to make room. An evicted agent would be refused until
// the log said something about it again, which a compacted log may never do, so
// the ceiling here is how many agents an estate has registered — a number the
// platform chooses, not one a caller can drive.
type Roster struct {
	mu    sync.RWMutex
	known map[string]decided
}

type decided struct {
	admits   bool
	tenant   string
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
	if err := tenant(record.GetTenantId()); err != nil {
		return err
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
	case seen && record.GetRevision() == held.revision && held.tenant != record.GetTenantId():
		r.known[record.GetAgentId()] = decided{revision: held.revision}
		return fmt.Errorf("%w: revision %d of agent %q places it in two tenants",
			ErrConflict, record.GetRevision(), record.GetAgentId())
	}
	r.known[record.GetAgentId()] = decided{
		admits:   state.Admits(),
		tenant:   record.GetTenantId(),
		revision: record.GetRevision(),
	}
	return nil
}

// What the platform holds about an agent whose record it could not read. The log
// is compacted and keyed by the agent, so that record is the whole of what was
// decided about it: stepping over it would keep admitting an agent it may have
// revoked, and the only safe reading of a decision nothing can read is that the
// agent is no longer admitted. The revision is kept so a later record still
// replaces it.
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

func (r *Roster) Admits(agentID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	held, seen := r.known[agentID]
	return !seen || held.admits
}

// The tenant an agent's telemetry is admitted into: the one the registry
// recorded it in, never one the agent or the gateway chose. An agent the
// registry never named has no tenant anybody decided, so it is not admitted —
// the certificate says who is sending, and only the registry says whose estate
// it belongs to.
func (r *Roster) Tenant(agentID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	held, seen := r.known[agentID]
	if !seen || !held.admits {
		return "", false
	}
	return held.tenant, true
}

func (r *Roster) Knows(agentID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, seen := r.known[agentID]
	return seen
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
