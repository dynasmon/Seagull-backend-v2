package broker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type Record struct {
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
}

type Deliver func(ctx context.Context, records []Record) error

type ConsumerConfig struct {
	Brokers      []string
	Topic        string
	Group        string
	ClientID     string
	MaxRecords   int
	FetchMaxWait time.Duration
	Metrics      *ConsumerMetrics
}

type Consumer struct {
	client     *kgo.Client
	topic      string
	group      string
	maxRecords int
	metrics    *ConsumerMetrics
}

// A new group starts at the beginning: telemetry that is already durable must
// not be skipped because a consumer was deployed after it arrived.
func NewConsumer(config ConsumerConfig) (*Consumer, error) {
	if len(config.Brokers) == 0 {
		return nil, errors.New("the backbone needs at least one broker address")
	}
	if config.Topic == "" {
		return nil, errors.New("the backbone needs a topic")
	}
	if config.Group == "" {
		return nil, errors.New("a backbone consumer needs a group")
	}
	if config.MaxRecords <= 0 {
		return nil, errors.New("a backbone consumer needs a positive record ceiling")
	}
	if config.Metrics == nil {
		return nil, errors.New("a backbone consumer needs metrics")
	}

	consumer := &Consumer{
		topic:      config.Topic,
		group:      config.Group,
		maxRecords: config.MaxRecords,
		metrics:    config.Metrics,
	}

	client, err := kgo.NewClient(
		kgo.SeedBrokers(config.Brokers...),
		kgo.ClientID(config.ClientID),
		kgo.ConsumerGroup(config.Group),
		kgo.ConsumeTopics(config.Topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.DisableAutoCommit(),
		kgo.BlockRebalanceOnPoll(),
		kgo.FetchMaxWait(config.FetchMaxWait),
		kgo.OnPartitionsRevoked(func(_ context.Context, _ *kgo.Client, revoked map[string][]int32) {
			consumer.metrics.forget(revoked)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("create backbone consumer: %w", err)
	}

	consumer.client = client
	return consumer, nil
}

// The position advances only once deliver has returned, so a crash replays a
// batch. At-least-once is a property of the backbone, not of each consumer.
func (c *Consumer) Consume(ctx context.Context, deliver Deliver) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		fetches := c.client.PollRecords(ctx, c.maxRecords)
		if fetches.IsClientClosed() {
			return errors.New("the backbone consumer was closed")
		}
		if err := ctx.Err(); err != nil {
			c.client.AllowRebalance()
			return err
		}

		c.report(fetches)
		records := collect(fetches)

		if len(records) > 0 {
			if err := deliver(ctx, records); err != nil {
				c.client.AllowRebalance()
				return err
			}
			if err := c.client.CommitUncommittedOffsets(ctx); err != nil {
				c.metrics.commitFailed()
				c.client.AllowRebalance()
				return fmt.Errorf("commit the group position on %s: %w", c.topic, err)
			}
		}
		c.client.AllowRebalance()
	}
}

func collect(fetches kgo.Fetches) []Record {
	total := fetches.NumRecords()
	if total == 0 {
		return nil
	}
	records := make([]Record, 0, total)
	fetches.EachRecord(func(record *kgo.Record) {
		records = append(records, Record{
			Partition: record.Partition,
			Offset:    record.Offset,
			Key:       record.Key,
			Value:     record.Value,
		})
	})
	return records
}

// A fetch error is not fatal: the client retries on its own, so the loop counts
// them and keeps consuming.
func (c *Consumer) report(fetches kgo.Fetches) {
	fetches.EachError(func(topic string, partition int32, err error) {
		if errors.Is(err, context.Canceled) {
			return
		}
		c.metrics.fetchFailed(topic, partition)
	})
	fetches.EachPartition(func(partition kgo.FetchTopicPartition) {
		c.metrics.observe(partition)
	})
}

func (c *Consumer) Ping(ctx context.Context) error {
	if err := c.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (c *Consumer) Close() { c.client.Close() }
