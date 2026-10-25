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
	ErrNoAgent      = errors.New("an observation names the agent that sent its event")
	ErrNoTime       = errors.New("an observation carries the event time it happened at")
	ErrValueTooLong = fmt.Errorf("an observed value is at most %d bytes", MaxValueLength)
)

// An event as the platform names it: by the agent the gateway read from the
// certificate the event was sent with, and by the identifier that agent gave
// it. The identifier is the producer's to choose and two agents can choose one
// alike, so it never names an event alone (ADR 38).
type EventName struct {
	Agent string
	ID    string
}

// What one event contributes to a key. Event names it, so a replayed batch
// counts once; At is event time, never the clock; Value is what a cardinality
// counts distinct of or the stage a sequence reached, empty when the rule only
// counts.
type Observation struct {
	Event EventName
	At    time.Time
	Value string

	// What the platform saw of the clock this event was timed by. Ordering is
	// decided in event time, which is the producer's, so a window read back for
	// a sequence carries how far that clock stood from the platform's own.
	Skew time.Duration
}

func (o Observation) Validate() error {
	switch {
	case o.Event.ID == "":
		return ErrNoEvent
	case o.Event.Agent == "":
		return ErrNoAgent
	case o.At.IsZero():
		return ErrNoTime
	case len(o.Value) > MaxValueLength:
		return ErrValueTooLong
	}
	return nil
}
