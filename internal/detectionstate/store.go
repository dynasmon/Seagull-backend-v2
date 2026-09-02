package detectionstate

import (
	"context"
	"errors"
	"time"
)

var (
	// Refused rather than evicted: whoever produces events produces group
	// values, and making room would let a flood of invented ones choose which
	// real counts an estate forgets.
	ErrAtCapacity = errors.New("the store is holding as many keys as it was bounded to")

	ErrTooLate = errors.New("an observation older than the window it belongs to cannot be folded into it")
)

// Where what a rule remembers is kept. One operation, applied atomically, so two
// events arriving at once cannot both read the count before either adds to it.
// Nothing here names a technology: an in-process keeper, a shared cache and a
// relational table are three implementations, chosen where adapters are chosen.
type Store interface {
	Observe(ctx context.Context, key Key, seen Observation, window time.Duration) (State, error)

	// The same fold, handing back what the key holds in event time. Folding and
	// reading are one operation because they have to be: a window read after a
	// separate fold is a window another event may have moved in between.
	Ordered(ctx context.Context, key Key, seen Observation, window time.Duration) (State, []Observation, error)
}
