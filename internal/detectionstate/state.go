package detectionstate

import "time"

// What a key holds after an observation: a threshold reads Count, a cardinality
// Distinct, a frequency both Count and Span, a temporal rule First and Last.
type State struct {
	First time.Time
	Last  time.Time

	Count    int
	Distinct int

	// The key is full, so Count is a floor: a threshold above the ceiling can
	// never be reached, which is why the ceiling is declared.
	Saturated bool

	// The key already held this event, so nothing moved. A caller decides on an
	// event the first time it is folded and never again, which is what keeps a
	// redelivered batch from deciding more than the delivery before it did.
	Repeated bool
}

func (s State) Span() time.Duration { return s.Last.Sub(s.First) }
