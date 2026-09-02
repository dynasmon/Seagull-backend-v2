package detectionstate

import (
	"errors"
	"fmt"
	"time"
)

// The longest field the event contract admits, and half of what makes the
// memory one key costs a number rather than a hope.
const MaxValueLength = 512

var (
	ErrNoEvent      = errors.New("an observation names the event it was made from")
	ErrNoTime       = errors.New("an observation carries the event time it happened at")
	ErrValueTooLong = fmt.Errorf("an observed value is at most %d bytes", MaxValueLength)
)

// What one event contributes to a key. Event carries the deterministic id, so a
// replayed batch counts once; At is event time, never the clock; Value is what a
// cardinality counts distinct of or the stage a sequence reached, empty when the
// rule only counts.
type Observation struct {
	Event string
	At    time.Time
	Value string

	// What the platform saw of the clock this event was timed by. Ordering is
	// decided in event time, which is the producer's, so a window read back for
	// a sequence carries how far that clock stood from the platform's own.
	Skew time.Duration
}

func (o Observation) Validate() error {
	switch {
	case o.Event == "":
		return ErrNoEvent
	case o.At.IsZero():
		return ErrNoTime
	case len(o.Value) > MaxValueLength:
		return ErrValueTooLong
	}
	return nil
}
