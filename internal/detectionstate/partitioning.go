package detectionstate

import (
	"errors"
	"fmt"
	"slices"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// The tenant is part of every key without ever being grouped by.
const tenantField = detection.Field("origin.tenant_id")

var (
	ErrNoPartitioning = errors.New("a stream states the fields its records are keyed by")
	ErrSplitState     = errors.New("a rule may not group by less than the stream is keyed by, because the events it counts reach readers that cannot see each other")
)

// What the backbone guarantees about which reader sees an event, and therefore
// which groups one store can hold the whole of. Events sharing a group that
// land on partitions this process does not hold are counted somewhere else,
// and neither count is the answer.
type Partitioning struct {
	By []detection.Field

	// Declared by a deployment and verified against its assignment, never
	// assumed.
	Sole bool
}

func (p Partitioning) Validate() error {
	if len(p.By) == 0 {
		return ErrNoPartitioning
	}
	for _, field := range p.By {
		if _, declared := detection.KindOf(field); !declared {
			return fmt.Errorf("%w: %q is not a field the contract declares", ErrNoPartitioning, field)
		}
	}
	return nil
}

func (p Partitioning) Colocates(group []detection.Field) bool {
	if len(p.By) == 0 {
		return false
	}
	for _, keyed := range p.By {
		if keyed != tenantField && !slices.Contains(group, keyed) {
			return false
		}
	}
	return true
}

func (p Partitioning) Admits(count detection.Count) error {
	if !count.Counts() || p.holds(count.GroupBy) {
		return nil
	}
	return ErrSplitState
}

func (p Partitioning) Orders(sequence detection.Sequence) error {
	if !sequence.Correlates() || p.holds(sequence.GroupBy) {
		return nil
	}
	return ErrSplitState
}

func (p Partitioning) holds(group []detection.Field) bool {
	return p.Sole || p.Colocates(group)
}
