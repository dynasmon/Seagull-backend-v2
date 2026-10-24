package broker

import (
	"context"
	"fmt"
	"maps"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

const lastRecordBudget = 30 * time.Second

// When the record just before each position was produced, read by a client of
// its own: the group session asking is held inside the assignment callback, so
// the reader's own client fetches nothing until the answer is returned. A
// partition whose record the topic no longer holds is absent from the answer.
func readLastRecordTimes(config ConsumerConfig, secured []kgo.Opt) func(context.Context, map[int32]int64) (map[int32]time.Time, error) {
	return func(ctx context.Context, positions map[int32]int64) (map[int32]time.Time, error) {
		times := make(map[int32]time.Time, len(positions))
		if len(positions) == 0 {
			return times, nil
		}

		from := make(map[int32]kgo.Offset, len(positions))
		for partition, position := range positions {
			from[partition] = kgo.NewOffset().At(position - 1)
		}
		client, err := kgo.NewClient(append([]kgo.Opt{
			kgo.SeedBrokers(config.Brokers...),
			kgo.ClientID(config.ClientID),
			kgo.ConsumePartitions(map[string]map[int32]kgo.Offset{config.Topic: from}),
			kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		}, secured...)...)
		if err != nil {
			return nil, fmt.Errorf("create a client to read the last records committed: %w", err)
		}
		defer client.Close()

		bounded, cancel := context.WithTimeout(ctx, lastRecordBudget)
		defer cancel()

		pending := maps.Clone(positions)
		for len(pending) > 0 {
			fetches := client.PollFetches(bounded)
			if err := bounded.Err(); err != nil {
				return nil, fmt.Errorf("read the last records committed to %s: %w", config.Topic, err)
			}
			if err := fetches.Err(); err != nil {
				return nil, fmt.Errorf("read the last records committed to %s: %w", config.Topic, err)
			}
			fetches.EachRecord(func(record *kgo.Record) {
				position, wanted := pending[record.Partition]
				if !wanted {
					return
				}
				delete(pending, record.Partition)
				if record.Offset == position-1 {
					times[record.Partition] = record.Timestamp
				}
			})
		}
		return times, nil
	}
}
