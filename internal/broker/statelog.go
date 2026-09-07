package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

// A compacted topic read whole rather than shared out. No consumer group and no
// committed position: this kind of topic carries state rather than work, so
// every process reads all of it rather than a share of it, and two engines hold
// the same records instead of half each.
type StateLog struct {
	client     *kgo.Client
	admin      *kadm.Client
	topic      string
	maxRecords int
}

func NewStateLog(config Config, maxRecords int) (*StateLog, error) {
	if len(config.Brokers) == 0 {
		return nil, errors.New("the backbone needs at least one broker address")
	}
	if config.Topic == "" {
		return nil, errors.New("the backbone needs a topic")
	}
	if maxRecords <= 0 {
		return nil, errors.New("a state reader needs a positive record ceiling")
	}

	secured, err := config.Security.options()
	if err != nil {
		return nil, err
	}

	client, err := kgo.NewClient(append([]kgo.Opt{
		kgo.SeedBrokers(config.Brokers...),
		kgo.ClientID(config.ClientID),
		kgo.ConsumeTopics(config.Topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	}, secured...)...)
	if err != nil {
		return nil, fmt.Errorf("create backbone client: %w", err)
	}
	return &StateLog{client: client, admin: kadm.NewClient(client), topic: config.Topic, maxRecords: maxRecords}, nil
}

// Everything written before this call, and then nothing. A process reads the
// whole log before it serves, so it never answers from a state it has only seen
// part of.
func (l *StateLog) Replay(ctx context.Context, deliver Deliver) error {
	ends, err := l.admin.ListEndOffsets(ctx, l.topic)
	if err != nil {
		return fmt.Errorf("read the end of %s: %w", l.topic, err)
	}

	remaining := make(map[int32]int64)
	ends.Each(func(offset kadm.ListedOffset) {
		if offset.Offset > 0 {
			remaining[offset.Partition] = offset.Offset
		}
	})

	for len(remaining) > 0 {
		records, err := l.poll(ctx)
		if err != nil {
			return fmt.Errorf("read %s to its end: %w", l.topic, err)
		}
		if err := deliver(ctx, records); err != nil {
			return err
		}
		for _, record := range records {
			if end, waiting := remaining[record.Partition]; waiting && record.Offset >= end-1 {
				delete(remaining, record.Partition)
			}
		}
	}
	return nil
}

// Everything written from here on, until the context ends.
func (l *StateLog) Follow(ctx context.Context, deliver Deliver) error {
	for {
		records, err := l.poll(ctx)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			continue
		}
		if err := deliver(ctx, records); err != nil {
			return err
		}
	}
}

func (l *StateLog) poll(ctx context.Context) ([]Record, error) {
	fetches := l.client.PollRecords(ctx, l.maxRecords)
	if fetches.IsClientClosed() {
		return nil, errors.New("the state reader was closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := fetches.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", l.topic, err)
	}
	return collect(fetches), nil
}

func (l *StateLog) Ping(ctx context.Context) error {
	if err := l.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (l *StateLog) Close() { l.client.Close() }

func (l *StateLog) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(l.client), topics)
}
