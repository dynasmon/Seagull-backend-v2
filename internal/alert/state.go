// Package alert states what becomes of a detection once a person is responsible
// for it: the states an alert passes through, which moves between them are
// legal, and what a move has to say for itself. It reads no store and serves no
// transport. Resolved and FalsePositive are both endings and they do not mean
// the same thing — the first says the platform was right and somebody dealt
// with it, the second says the platform was wrong, and it is the only signal a
// rule author has that a rule needs correcting. Nothing collapses them.
package alert

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
)

const SchemaVersion = 1

var ErrIllegalMove = errors.New("the alert does not move that way")

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

// Where an alert may go from where it is. Triage runs forwards and the only way
// back is out of an ending, which returns to the beginning rather than to the
// middle: an alert somebody reopens has not been acknowledged again.
var moves = map[State][]State{
	Open:            {Acknowledged, InInvestigation, Resolved, FalsePositive},
	Acknowledged:    {InInvestigation, Resolved, FalsePositive},
	InInvestigation: {Resolved, FalsePositive},
	Resolved:        {Open},
	FalsePositive:   {Open},
}

func Legal(from, to State) bool { return slices.Contains(moves[from], to) }

func Reachable(from State) []State { return slices.Clone(moves[from]) }

// Closing as a false positive and reopening a closed alert both say an earlier
// decision was wrong, and neither is worth recording without the why. Resolving
// needs no reason, which is what makes the two endings different acts rather
// than one act wearing two labels.
func Explains(from, to State) bool { return to == FalsePositive || from.Closed() }

func Illegal(from, to State) error {
	if !to.Valid() {
		return fmt.Errorf("%w: %q names no alert state; there are %s", ErrIllegalMove, to, join(states))
	}
	if from == to {
		return fmt.Errorf("%w: the alert is already %s", ErrIllegalMove, to)
	}
	reachable := Reachable(from)
	if len(reachable) == 0 {
		return fmt.Errorf("%w: an alert that is %s goes nowhere", ErrIllegalMove, from)
	}
	return fmt.Errorf("%w: an alert that is %s does not become %s; it becomes %s",
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
// what a caller is told an alert is.
var wire = map[State]alertv1.State{
	Open:            alertv1.State_STATE_OPEN,
	Acknowledged:    alertv1.State_STATE_ACKNOWLEDGED,
	InInvestigation: alertv1.State_STATE_IN_INVESTIGATION,
	Resolved:        alertv1.State_STATE_RESOLVED,
	FalsePositive:   alertv1.State_STATE_FALSE_POSITIVE,
}

func (s State) Wire() alertv1.State { return wire[s] }

func FromWire(state alertv1.State) (State, bool) {
	for named, value := range wire {
		if value == state {
			return named, true
		}
	}
	return "", false
}
