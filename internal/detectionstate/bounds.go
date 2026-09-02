package detectionstate

import (
	"errors"
	"fmt"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// Two of the three are the rule language's own ceilings rather than numbers of
// this package's choosing: a rule may ask for a window and a count, and a store
// that held less than the most a rule may ask for would be one where a rule
// that compiled could never fire. A window is also what a restart costs —
// rebuilding state means reading that much of the backbone again.
const (
	MaxWindow             = detection.MaxWithin
	MaxObservationsPerKey = detection.MaxCount
	MaxKeys               = 1 << 20
)

var (
	ErrNoWindow       = fmt.Errorf("a state window is positive and at most %s", MaxWindow)
	ErrNoObservations = fmt.Errorf("a key holds between 1 and %d observations", MaxObservationsPerKey)
	ErrNoKeys         = fmt.Errorf("a store holds between 1 and %d keys", MaxKeys)
	ErrWindowTooLong  = errors.New("a rule may not remember for longer than the store was bounded to")
	ErrUnreachable    = errors.New("a rule may not count to more than one key of this store holds")
	ErrUnorderable    = errors.New("a rule may not order more stages than one key of this store holds")
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

// Whether a store bounded this way could ever answer what a rule asks. The
// compiler refuses a rule against the ceilings every store shares; this is the
// one a deployment chose, and a rule it cannot answer is a rule that would run
// and never fire.
func (b Bounds) Admits(count detection.Count) error {
	switch {
	case !count.Counts():
		return nil
	case count.Within > b.Window:
		return ErrWindowTooLong
	case count.AtLeast > b.ObservationsPerKey:
		return ErrUnreachable
	}
	return nil
}

// The same question for a rule that orders rather than counts. A key holding
// fewer observations than the sequence has stages could never hold the whole of
// one, so the story would be assembled and never completed.
func (b Bounds) Orders(sequence detection.Sequence) error {
	switch {
	case !sequence.Correlates():
		return nil
	case sequence.Within > b.Window:
		return ErrWindowTooLong
	case len(sequence.Stages) > b.ObservationsPerKey:
		return ErrUnorderable
	}
	return nil
}
