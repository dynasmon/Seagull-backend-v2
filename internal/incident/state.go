// Package incident states what a correlation becomes once a person is
// responsible for it: the states an incident passes through, which moves
// between them are legal, and what a move has to say for itself. It reads no
// store and serves no transport. An incident is not an alert and this package
// does not name that one: closing a story is not closing any of the work it is
// made of, and the day one of them needs a state the other does not, neither has
// to ask the other's permission.
package incident

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

const SchemaVersion = 1

var ErrIllegalMove = errors.New("the incident does not move that way")

type State string

const (
	Open            State = "open"
	Acknowledged    State = "acknowledged"
	InInvestigation State = "in_investigation"
	Resolved        State = "resolved"
	FalsePositive   State = "false_positive"
)

var states = []State{Open, Acknowledged, InInvestigation, Resolved, FalsePositive}

func States() []State { return slices.Clone(states) }

func (s State) Valid() bool { return slices.Contains(states, s) }

func (s State) String() string { return string(s) }

func (s State) Closed() bool { return s == Resolved || s == FalsePositive }

// Where an incident may go from where it is. Triage runs forwards and the only
// way back is out of an ending, which returns to the beginning rather than to
// the middle: a story somebody reopens has not been acknowledged again.
var moves = map[State][]State{
	Open:            {Acknowledged, InInvestigation, Resolved, FalsePositive},
	Acknowledged:    {InInvestigation, Resolved, FalsePositive},
	InInvestigation: {Resolved, FalsePositive},
	Resolved:        {Open},
	FalsePositive:   {Open},
}

func Legal(from, to State) bool { return slices.Contains(moves[from], to) }

func Reachable(from State) []State { return slices.Clone(moves[from]) }

// Closing a story as a false positive says the events were not the story the
// rule read them as, which is the only signal a correlation rule's author gets
// that the stages or the window are wrong. Reopening says an earlier reading was
// wrong. Neither is worth recording without the why; resolving is.
func Explains(from, to State) bool { return to == FalsePositive || from.Closed() }

func Illegal(from, to State) error {
	if !to.Valid() {
		return fmt.Errorf("%w: %q names no incident state; there are %s", ErrIllegalMove, to, join(states))
	}
	if from == to {
		return fmt.Errorf("%w: the incident is already %s", ErrIllegalMove, to)
	}
	reachable := Reachable(from)
	if len(reachable) == 0 {
		return fmt.Errorf("%w: an incident that is %s goes nowhere", ErrIllegalMove, from)
	}
	return fmt.Errorf("%w: an incident that is %s does not become %s; it becomes %s",
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
// what a caller is told an incident is.
var wire = map[State]incidentv1.State{
	Open:            incidentv1.State_STATE_OPEN,
	Acknowledged:    incidentv1.State_STATE_ACKNOWLEDGED,
	InInvestigation: incidentv1.State_STATE_IN_INVESTIGATION,
	Resolved:        incidentv1.State_STATE_RESOLVED,
	FalsePositive:   incidentv1.State_STATE_FALSE_POSITIVE,
}

func (s State) Wire() incidentv1.State { return wire[s] }

func FromWire(state incidentv1.State) (State, bool) {
	for named, value := range wire {
		if value == state {
			return named, true
		}
	}
	return "", false
}
