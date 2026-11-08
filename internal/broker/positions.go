package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

// How far the owners of the platform's streams have got, for a reader that
// reads what they stored rather than what they read: a group's committed
// offset is the next record it will read, so everything before it was made
// durable by the owner before the position moved.
type Positions struct {
	client *kgo.Client
	admin  *kadm.Client
}

func NewPositions(brokers []string, clientID string, security Security) (*Positions, error) {
	if len(brokers) == 0 {
		return nil, errors.New("the backbone needs at least one broker address")
	}
	secured, err := security.options()
	if err != nil {
		return nil, err
	}
	client, err := kgo.NewClient(append([]kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ClientID(clientID),
	}, secured...)...)
	if err != nil {
		return nil, fmt.Errorf("create a backbone client to read positions: %w", err)
	}
	return &Positions{client: client, admin: kadm.NewClient(client)}, nil
}

// The next offset the group will read on each partition of the topic it has
// committed on; a partition it never committed is absent.
func (p *Positions) Committed(ctx context.Context, group, topic string) (map[int32]int64, error) {
	offsets, err := p.admin.FetchOffsets(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("read where %s stands on %s: %w", group, topic, err)
	}
	if err := offsets.Error(); err != nil {
		return nil, fmt.Errorf("read where %s stands on %s: %w", group, topic, err)
	}
	committed := map[int32]int64{}
	offsets.Each(func(offset kadm.OffsetResponse) {
		if offset.Topic == topic && offset.At >= 0 {
			committed[offset.Partition] = offset.At
		}
	})
	return committed, nil
}

// The offset the next record of each partition will be written at.
func (p *Positions) Ends(ctx context.Context, topic string) (map[int32]int64, error) {
	listed, err := p.admin.ListEndOffsets(ctx, topic)
	if err != nil {
		return nil, fmt.Errorf("read where %s ends: %w", topic, err)
	}
	ends := map[int32]int64{}
	var failed error
	listed.Each(func(offset kadm.ListedOffset) {
		if offset.Err != nil {
			failed = fmt.Errorf("read where partition %d of %s ends: %w", offset.Partition, topic, offset.Err)
			return
		}
		ends[offset.Partition] = offset.Offset
	})
	if failed != nil {
		return nil, failed
	}
	if len(ends) == 0 {
		return nil, fmt.Errorf("the backbone named no partition of %s", topic)
	}
	return ends, nil
}

func (p *Positions) Ping(ctx context.Context) error {
	if err := p.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (p *Positions) Close() { p.client.Close() }
