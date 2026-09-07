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
