package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

const rulesetSchema = "seagull.ruleset.v1.Record"

// The one key an activation is ever written under. Every published ruleset is
// keyed by its own content id, so compaction keeps all of them for as long as
// the platform lives, and keeps only the last record written here — which is
// what makes this key the pointer and every other key an immutable version.
const ActiveKey = "active"

type Rulesets struct {
	client *kgo.Client
	topic  string
}

func NewRulesets(config Config) (*Rulesets, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Rulesets{client: client, topic: config.Topic}, nil
}

func (r *Rulesets) Publish(ctx context.Context, record *rulesetv1.Record) error {
	key, err := keyOf(record)
	if err != nil {
		return err
	}
	encoded, err := proto.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode ruleset record %s: %w", key, err)
	}

	written := &kgo.Record{
		Topic: r.topic,
		Key:   []byte(key),
		Value: encoded,
		Headers: []kgo.RecordHeader{
			{Key: "content-type", Value: []byte(contentType)},
			{Key: "schema", Value: []byte(rulesetSchema)},
		},
	}
	if err := r.client.ProduceSync(ctx, written).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", r.topic, err)
	}
	return nil
}

func keyOf(record *rulesetv1.Record) (string, error) {
	switch held := record.GetRecord().(type) {
	case *rulesetv1.Record_Version:
		if held.Version.GetId() == "" {
			return "", errors.New("a published ruleset is keyed by the id it is named by, and this one carries none")
		}
		return held.Version.GetId(), nil
	case *rulesetv1.Record_Active:
		if held.Active.GetRulesetId() == "" {
			return "", errors.New("an activation names the ruleset it activates")
		}
		return ActiveKey, nil
	default:
		return "", errors.New("a ruleset record carries nothing to publish")
	}
}

func (r *Rulesets) Ping(ctx context.Context) error {
	if err := r.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (r *Rulesets) Close() { r.client.Close() }

func (r *Rulesets) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(r.client), topics)
}

type RulesetLog struct {
	client     *kgo.Client
	admin      *kadm.Client
	topic      string
	maxRecords int
}

// No consumer group and no committed position: this topic carries state rather
// than work, so every process reads all of it rather than a share of it, and
// two engines hold the same rulesets instead of half each.
func NewRulesetLog(config Config, maxRecords int) (*RulesetLog, error) {
	if len(config.Brokers) == 0 {
		return nil, errors.New("the backbone needs at least one broker address")
	}
	if config.Topic == "" {
		return nil, errors.New("the backbone needs a topic")
	}
	if maxRecords <= 0 {
		return nil, errors.New("a ruleset reader needs a positive record ceiling")
	}

	client, err := kgo.NewClient(
		kgo.SeedBrokers(config.Brokers...),
		kgo.ClientID(config.ClientID),
		kgo.ConsumeTopics(config.Topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		return nil, fmt.Errorf("create backbone client: %w", err)
	}
	return &RulesetLog{client: client, admin: kadm.NewClient(client), topic: config.Topic, maxRecords: maxRecords}, nil
}

// Everything written before this call, and then nothing. A process reads the
// whole log before it serves, so it never answers about a ruleset estate it has
// only seen part of.
func (l *RulesetLog) Replay(ctx context.Context, deliver Deliver) error {
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
func (l *RulesetLog) Follow(ctx context.Context, deliver Deliver) error {
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

func (l *RulesetLog) poll(ctx context.Context) ([]Record, error) {
	fetches := l.client.PollRecords(ctx, l.maxRecords)
	if fetches.IsClientClosed() {
		return nil, errors.New("the ruleset reader was closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := fetches.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", l.topic, err)
	}
	return collect(fetches), nil
}

func (l *RulesetLog) Ping(ctx context.Context) error {
	if err := l.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (l *RulesetLog) Close() { l.client.Close() }

func (l *RulesetLog) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(l.client), topics)
}
