package broker

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// What a reader must re-read before its answers are correct again, asked every
// time the group hands it partitions. State held in a process does not move
// with a partition, so a reader resuming at the committed position resumes
// with a window it never observed. A refusal stops the reader instead.
//
// It is told what it holds and not what the topic has: the topology declares
// the partition count, VerifyTopics refuses to serve when the broker disagrees,
// and the migrator refuses to repartition, so the number is already known
// without asking the brokers again at every rebalance.
type Recovery func(held int32) (time.Duration, error)

// Deciding the replayed suffix again writes what it already wrote, because a
// detection is named by the rule and the events it was decided from.
func (c *Consumer) rebuild(ctx context.Context, offsets map[string]map[int32]kgo.Offset) (map[string]map[int32]kgo.Offset, error) {
	if c.recovery == nil {
		return offsets, nil
	}

	window, err := c.recovery(c.holding())
	if err != nil {
		return nil, c.refuse(err)
	}
	if window <= 0 || len(offsets[c.topic]) == 0 {
		return offsets, nil
	}
	return c.rewind(ctx, offsets, window)
}

func (c *Consumer) rewind(ctx context.Context, offsets map[string]map[int32]kgo.Offset, window time.Duration) (map[string]map[int32]kgo.Offset, error) {
	from := time.Now().Add(-window)
	listed, err := c.endOffsets.ListOffsetsAfterMilli(ctx, from.UnixMilli(), c.topic)
	if err != nil {
		return nil, c.refuse(fmt.Errorf("read back %s of %s to rebuild detection state: %w", window, c.topic, err))
	}

	rebuilt := maps.Clone(offsets)
	rebuilt[c.topic] = maps.Clone(offsets[c.topic])
	for partition, position := range offsets[c.topic] {
		committed := position.EpochOffset().Offset
		earliest, found := listed.Lookup(c.topic, partition)
		if committed < 0 || !found || earliest.Err != nil || earliest.Offset < 0 || earliest.Offset >= committed {
			continue
		}
		rebuilt[c.topic][partition] = kgo.NewOffset().At(earliest.Offset).WithEpoch(-1)
		c.metrics.rebuilt(c.topic, committed-earliest.Offset)
	}
	return rebuilt, nil
}

func (c *Consumer) took(assigned map[string][]int32) {
	c.mu.Lock()
	for _, partition := range assigned[c.topic] {
		c.assigned[partition] = struct{}{}
	}
	held := len(c.assigned)
	c.mu.Unlock()

	c.metrics.moved(c.topic, "assigned", len(assigned[c.topic]))
	c.metrics.holding(c.topic, held)
}

func (c *Consumer) gave(revoked map[string][]int32) {
	c.mu.Lock()
	for _, partition := range revoked[c.topic] {
		delete(c.assigned, partition)
	}
	held := len(c.assigned)
	c.mu.Unlock()

	c.metrics.moved(c.topic, "revoked", len(revoked[c.topic]))
	c.metrics.holding(c.topic, held)
	c.answerable(int32(held))
}

// Losing a partition changes what a reader can answer as much as gaining one
// does, and a member that only loses them is never asked for offsets to adjust.
func (c *Consumer) answerable(held int32) {
	if c.recovery == nil {
		return
	}
	if _, err := c.recovery(held); err != nil {
		c.refuse(err)
	}
}

func (c *Consumer) holding() int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int32(len(c.assigned))
}

// Held rather than only returned: the group session that asked is not the
// caller waiting on Consume, and rejoining would meet the same topology.
func (c *Consumer) refuse(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refusal == nil {
		c.refusal = err
	}
	return err
}

func (c *Consumer) refused() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refusal
}

func (c *Consumer) Assigned() []int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Sorted(maps.Keys(c.assigned))
}
