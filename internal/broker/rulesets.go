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

// The one key an activation pointer is ever written under, and the prefix each
// record of an activation happening is written under instead. Every published
// ruleset is keyed by its own content id, so compaction keeps all of them for as
// long as the platform lives; it keeps only the last record written under
// ActiveKey, which is what makes that key the desired state and every other key
// on this topic something nothing removes.
const ActiveKey = "active"

// Whether a record read off this topic is the pointer or something the log
// keeps. Which one an activation is is a property of the key, and the key
// belongs here rather than to whoever reads the record.
func Desired(key []byte) bool { return string(key) == ActiveKey }

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
	version, published := record.GetRecord().(*rulesetv1.Record_Version)
	if !published {
		return errors.New("a version is what is published to this topic; an activation is activated")
	}
	if version.Version.GetId() == "" {
		return errors.New("a published ruleset is keyed by the id it is named by, and this one carries none")
	}

	stored, err := keyed(r.topic, version.Version.GetId(), record)
	if err != nil {
		return err
	}
	return r.produce(ctx, stored)
}

// Twice, in one produce and in this order: the line of the trail first, under a
// key nothing writes again, then the pointer under the key compaction keeps only
// the last of. A produce that stops between the two leaves a recorded activation
// with no pointer and the estate running what it was already running; the other
// order would move it onto a ruleset the trail never recorded.
func (r *Rulesets) Activate(ctx context.Context, key string, active *rulesetv1.Active) error {
	if active.GetRulesetId() == "" {
		return errors.New("an activation names the ruleset it activates")
	}
	if key == "" || key == ActiveKey {
		return errors.New("a recorded activation is keyed by what happened, under a key nothing writes twice")
	}
	record := &rulesetv1.Record{Record: &rulesetv1.Record_Active{Active: active}}

	trail, err := keyed(r.topic, key, record)
	if err != nil {
		return err
	}
	pointer, err := keyed(r.topic, ActiveKey, record)
	if err != nil {
		return err
	}
	return r.produce(ctx, trail, pointer)
}

func (r *Rulesets) produce(ctx context.Context, records ...*kgo.Record) error {
	if err := r.client.ProduceSync(ctx, records...).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", r.topic, err)
	}
	return nil
}

func keyed(topic, key string, record *rulesetv1.Record) (*kgo.Record, error) {
	encoded, err := proto.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode ruleset record %s: %w", key, err)
	}
	return &kgo.Record{
		Topic: topic,
		Key:   []byte(key),
		Value: encoded,
		Headers: []kgo.RecordHeader{
			{Key: "content-type", Value: []byte(contentType)},
			{Key: "schema", Value: []byte(rulesetSchema)},
		},
	}, nil
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
