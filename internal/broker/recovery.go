package broker

import (
	"context"
	"fmt"
	"log/slog"
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
// detection is named by the rule and the events it was decided from. The window
// is measured back from the last record each partition committed and never from
// the clock: a reader stopped or behind for longer than the window was still in
// the middle of one, and a window the topic no longer holds is reported.
func (c *Consumer) rebuild(ctx context.Context, offsets map[string]map[int32]kgo.Offset) (map[string]map[int32]kgo.Offset, error) {
	if c.recovery == nil {
		return offsets, nil
	}

	topic := c.topics[0]
	window, err := c.recovery(c.held(topic))
	if err != nil {
		return nil, c.refuse(err)
	}
	if window <= 0 || len(offsets[topic]) == 0 {
		return offsets, nil
	}
	return c.rewind(ctx, topic, offsets, window)
}

func (c *Consumer) rewind(ctx context.Context, topic string, offsets map[string]map[int32]kgo.Offset, window time.Duration) (map[string]map[int32]kgo.Offset, error) {
	committed := make(map[int32]int64, len(offsets[topic]))
	for partition, position := range offsets[topic] {
		if offset := position.EpochOffset().Offset; offset > 0 {
			committed[partition] = offset
		}
	}
	if len(committed) == 0 {
		return offsets, nil
	}

	starts, err := c.endOffsets.ListStartOffsets(ctx, topic)
	if err != nil {
		return nil, c.refuse(fmt.Errorf("read where %s starts to rebuild detection state: %w", topic, err))
	}
	held := make(map[int32]int64, len(committed))
	for partition, position := range committed {
		start, found := starts.Lookup(topic, partition)
		switch {
		case found && start.Err != nil:
			return nil, c.refuse(fmt.Errorf("read where partition %d of %s starts: %w", partition, topic, start.Err))
		case !found || start.Offset < 0:
			return nil, c.refuse(fmt.Errorf("the backbone did not say where partition %d of %s starts", partition, topic))
		}
		switch {
		case position < start.Offset:
			c.cut(topic, partition, position, "undecided_records_gone")
		case position-1 < start.Offset:
			c.cut(topic, partition, position, "last_committed_record_gone")
		default:
			held[partition] = position
		}
	}
	if len(held) == 0 {
		return offsets, nil
	}

	stopped, err := c.lastRecordTimes(ctx, held)
	if err != nil {
		return nil, c.refuse(fmt.Errorf("read the last records %s committed to rebuild detection state: %w", topic, err))
	}
	from := make(map[int32]int64, len(held))
	for partition, position := range held {
		last, found := stopped[partition]
		if !found {
			c.cut(topic, partition, position, "last_committed_record_gone")
			continue
		}
		from[partition] = last.Add(-window).UnixMilli()
	}
	if len(from) == 0 {
		return offsets, nil
	}

	listed, err := c.endOffsets.ListOffsetsAfter(ctx, topic, from)
	if err != nil {
		return nil, c.refuse(fmt.Errorf("read back %s of %s to rebuild detection state: %w", window, topic, err))
	}
	rebuilt := maps.Clone(offsets)
	rebuilt[topic] = maps.Clone(offsets[topic])
	for partition := range from {
		position := held[partition]
		earliest, found := listed.Lookup(topic, partition)
		if !found || earliest.Err != nil || earliest.Offset < 0 || earliest.Offset >= position {
			continue
		}
		rebuilt[topic][partition] = kgo.NewOffset().At(earliest.Offset).WithEpoch(-1)
		c.metrics.rebuilt(topic, position-earliest.Offset)
	}
	return rebuilt, nil
}

func (c *Consumer) cut(topic string, partition int32, position int64, reason string) {
	c.metrics.cut(topic, partition)
	c.logger.Warn("state_rebuild_incomplete",
		slog.String("topic", topic),
		slog.Int("partition", int(partition)),
		slog.Int64("position", position),
		slog.String("reason", reason),
	)
}

func (c *Consumer) took(assigned map[string][]int32) {
	c.mu.Lock()
	for _, topic := range c.topics {
		if c.assigned[topic] == nil {
			c.assigned[topic] = make(map[int32]struct{})
		}
		for _, partition := range assigned[topic] {
			c.assigned[topic][partition] = struct{}{}
		}
	}
	held := c.heldLocked()
	c.mu.Unlock()

	for _, topic := range c.topics {
		c.metrics.moved(topic, "assigned", len(assigned[topic]))
		c.metrics.holding(topic, int(held[topic]))
	}
	c.owned(held)
}

func (c *Consumer) gave(revoked map[string][]int32) {
	c.mu.Lock()
	for _, topic := range c.topics {
		for _, partition := range revoked[topic] {
			delete(c.assigned[topic], partition)
		}
	}
	held := c.heldLocked()
	c.mu.Unlock()

	for _, topic := range c.topics {
		c.metrics.moved(topic, "revoked", len(revoked[topic]))
		c.metrics.holding(topic, int(held[topic]))
	}
	c.answerable(held[c.topics[0]])
	c.owned(held)
}

// Losing a partition changes what a reader can answer as much as gaining one
// does, and a member that only loses them is never asked for offsets to adjust.
func (c *Consumer) answerable(held int32) {
	if c.recovery == nil {
		return
	}
	if _, err := c.recovery(held); err != nil {
		_ = c.refuse(err)
	}
}

func (c *Consumer) held(topic string) int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int32(len(c.assigned[topic]))
}

func (c *Consumer) heldLocked() map[string]int32 {
	held := make(map[string]int32, len(c.topics))
	for _, topic := range c.topics {
		held[topic] = int32(len(c.assigned[topic]))
	}
	return held
}

// Held rather than only returned: the group session that asked is not the
// caller waiting on Consume, and rejoining would meet the same topology.
func (c *Consumer) refuse(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refusal == nil {
		c.refusal = err
		if c.interrupt != nil {
			c.interrupt()
		}
	}
	return err
}

func (c *Consumer) refused() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refusal
}

func (c *Consumer) Assigned(topic string) []int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Sorted(maps.Keys(c.assigned[topic]))
}
