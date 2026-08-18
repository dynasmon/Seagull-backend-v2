package broker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

const (
	lagRefreshInterval = 5 * time.Second
	lagRefreshTimeout  = 2 * time.Second
)

type endOffsetReader interface {
	ListEndOffsets(ctx context.Context, topics ...string) (kadm.ListedOffsets, error)
}

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
	endOffsets endOffsetReader
}

// New groups start at the earliest durable telemetry.
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
	consumer.endOffsets = kadm.NewClient(client)
	return consumer, nil
}

// Commit only after delivery so crashes replay the batch.
func (c *Consumer) Consume(ctx context.Context, deliver Deliver) error {
	monitorCtx, stopMonitor := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		c.monitorLag(monitorCtx)
	}()
	defer func() {
		stopMonitor()
		<-monitorDone
	}()

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
			c.metrics.committed(fetches)
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

// Fetch errors are counted while franz-go performs its own retries.
func (c *Consumer) report(fetches kgo.Fetches) {
	committed := c.client.CommittedOffsets()
	fetches.EachError(func(topic string, partition int32, err error) {
		if errors.Is(err, context.Canceled) {
			return
		}
		c.metrics.fetchFailed(topic, partition)
	})
	fetches.EachPartition(func(partition kgo.FetchTopicPartition) {
		next := int64(-1)
		if partitions := committed[partition.Topic]; partitions != nil {
			if position, exists := partitions[partition.Partition]; exists {
				next = position.Offset
			}
		}
		c.metrics.observe(partition, next)
	})
}

func (c *Consumer) monitorLag(ctx context.Context) {
	ticker := time.NewTicker(lagRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.refreshLag(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (c *Consumer) refreshLag(ctx context.Context) {
	if !c.metrics.tracks(c.topic) {
		return
	}
	refreshCtx, cancel := context.WithTimeout(ctx, lagRefreshTimeout)
	defer cancel()

	offsets, err := c.endOffsets.ListEndOffsets(refreshCtx, c.topic)
	failed := err != nil
	offsets.Each(func(offset kadm.ListedOffset) {
		if offset.Err != nil || offset.Offset < 0 {
			failed = true
			return
		}
		c.metrics.refresh(offset.Topic, offset.Partition, offset.Offset)
	})
	if failed && ctx.Err() == nil {
		c.metrics.lagRefreshFailed(c.topic)
	}
}

func (c *Consumer) Ping(ctx context.Context) error {
	if err := c.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (c *Consumer) Close() { c.client.Close() }
