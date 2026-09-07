// Package agent states what the platform decided about a machine it takes
// telemetry from: the states an agent passes through, which moves between them
// are legal, and which of them still admit what it sends. It reads no store and
// serves no transport. Identity is a separate concern and stays one — the
// gateway reads it off the certificate, and this package only says when an
// identity stops being honoured.
package agent

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const SchemaVersion = 1

var ErrIllegalMove = errors.New("the agent does not move that way")

type State string

const (
	Pending        State = "pending"
	Active         State = "active"
	Disabled       State = "disabled"
	Revoked        State = "revoked"
	Decommissioned State = "decommissioned"
)

var states = []State{Pending, Active, Disabled, Revoked, Decommissioned}

func States() []State { return slices.Clone(states) }

func (s State) Valid() bool { return slices.Contains(states, s) }

func (s State) String() string { return string(s) }

func (s State) Final() bool { return s == Revoked || s == Decommissioned }

// Whether telemetry carrying this agent's identity is still taken. A registered
// agent is admitted the moment it holds a certificate, so registering one never
// takes away what an unregistered one could do; what the registry adds is the
// ability to stop.
func (s State) Admits() bool { return s == Pending || s == Active }

// Where an agent may go from where it is. Revoking and decommissioning are
// endings with no way back, because the data plane knows an agent by its
// identifier alone: an identifier that returned would re-admit the certificate
// that was revoked alongside whichever one replaced it. A machine that comes
// back comes back as a new agent.
var moves = map[State][]State{
	Pending:  {Disabled, Revoked, Decommissioned},
	Active:   {Disabled, Revoked, Decommissioned},
	Disabled: {Active, Revoked, Decommissioned},
}

func Legal(from, to State) bool { return slices.Contains(moves[from], to) }

func Reachable(from State) []State { return slices.Clone(moves[from]) }

func Illegal(from, to State) error {
	if !to.Valid() {
		return fmt.Errorf("%w: %q names no agent state; there are %s", ErrIllegalMove, to, join(states))
	}
	if from == to {
		return fmt.Errorf("%w: the agent is already %s", ErrIllegalMove, to)
	}
	reachable := Reachable(from)
	if len(reachable) == 0 {
		return fmt.Errorf("%w: an agent that is %s goes nowhere", ErrIllegalMove, from)
	}
	return fmt.Errorf("%w: an agent that is %s does not become %s; it becomes %s",
		ErrIllegalMove, from, to, join(reachable))
}

func join[T ~string](values []T) string {
	written := make([]string, len(values))
	for index, value := range values {
		written[index] = string(value)
	}
	return strings.Join(written, ", ")
}

// Mapped explicitly in both directions rather than by name, so renaming a
// constant on either side is a compile error here instead of a silent change in
// what a caller is told an agent is.
var wire = map[State]agentv1.State{
	Pending:        agentv1.State_STATE_PENDING,
	Active:         agentv1.State_STATE_ACTIVE,
	Disabled:       agentv1.State_STATE_DISABLED,
	Revoked:        agentv1.State_STATE_REVOKED,
	Decommissioned: agentv1.State_STATE_DECOMMISSIONED,
}

func (s State) Wire() agentv1.State { return wire[s] }

func FromWire(state agentv1.State) (State, bool) {
	for named, value := range wire {
		if value == state {
			return named, true
		}
	}
	return "", false
}
