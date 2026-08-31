package detectionstate

import (
	"errors"
	"fmt"
	"time"
)

// A window is also what a restart costs: rebuilding state means reading that
// much of the backbone again.
const (
	MaxWindow             = 24 * time.Hour
	MaxObservationsPerKey = 4096
	MaxKeys               = 1 << 20
)

var (
	ErrNoWindow       = fmt.Errorf("a state window is positive and at most %s", MaxWindow)
	ErrNoObservations = fmt.Errorf("a key holds between 1 and %d observations", MaxObservationsPerKey)
	ErrNoKeys         = fmt.Errorf("a store holds between 1 and %d keys", MaxKeys)
	ErrWindowTooLong  = errors.New("a rule may not remember for longer than the store was bounded to")
)

// All three are finite and declared, so the memory a store can occupy is known
// before it runs rather than discovered under load.
type Bounds struct {
	Window             time.Duration
	ObservationsPerKey int
	Keys               int
}

func (b Bounds) Validate() error {
	switch {
	case b.Window <= 0 || b.Window > MaxWindow:
		return ErrNoWindow
	case b.ObservationsPerKey <= 0 || b.ObservationsPerKey > MaxObservationsPerKey:
		return ErrNoObservations
	case b.Keys <= 0 || b.Keys > MaxKeys:
		return ErrNoKeys
	}
	return nil
}

func (b Bounds) Observations() int { return b.Keys * b.ObservationsPerKey }
