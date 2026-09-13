package broker

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

const advisorySchema = "seagull.vulnerability.v1.Record"

var advisorySchemaVersion = strconv.Itoa(vulnerability.SchemaVersion)

// Where the platform's vulnerability intelligence lives: every advisory it
// holds, under its own key, and the newest word on how fresh each feed is.
type Advisories struct {
	client *kgo.Client
	topic  string
}

func NewAdvisories(config Config) (*Advisories, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Advisories{client: client, topic: config.Topic}, nil
}

func (a *Advisories) Publish(ctx context.Context, records []*vulnerabilityv1.Record) error {
	if len(records) == 0 {
		return nil
	}

	written := make([]*kgo.Record, 0, len(records))
	for _, entry := range records {
		key, err := advisoryKey(entry)
		if err != nil {
			return err
		}
		encoded, err := proto.Marshal(entry)
		if err != nil {
			return fmt.Errorf("encode advisory record %s: %w", key, err)
		}
		written = append(written, &kgo.Record{
			Topic: a.topic,
			Key:   key,
			Value: encoded,
			Headers: []kgo.RecordHeader{
				{Key: "content-type", Value: []byte(contentType)},
				{Key: "schema", Value: []byte(advisorySchema)},
				{Key: "schema-version", Value: []byte(advisorySchemaVersion)},
			},
		})
	}

	if err := a.client.ProduceSync(ctx, written...).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", a.topic, err)
	}
	return nil
}

// An advisory is keyed by its source and the id it has there, so compaction
// keeps the newest version of each and no two advisories ever replace each
// other; a feed sync by its feed, in a namespace of its own.
func advisoryKey(record *vulnerabilityv1.Record) ([]byte, error) {
	switch body := record.GetRecord().(type) {
	case *vulnerabilityv1.Record_Advisory:
		if body.Advisory.GetSource() == "" || body.Advisory.GetId() == "" {
			return nil, errors.New("an advisory is keyed by its source and id, and this one lacks one")
		}
		return []byte("advisory/" + body.Advisory.GetSource() + "/" + body.Advisory.GetId()), nil
	case *vulnerabilityv1.Record_Sync:
		if body.Sync.GetSource() == "" || body.Sync.GetFeed() == "" {
			return nil, errors.New("a feed sync is keyed by its source and feed, and this one lacks one")
		}
		return []byte("feed/" + body.Sync.GetSource() + "/" + body.Sync.GetFeed()), nil
	default:
		return nil, errors.New("an advisory record carries neither an advisory nor a feed sync")
	}
}

func (a *Advisories) Ping(ctx context.Context) error {
	if err := a.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (a *Advisories) Close() { a.client.Close() }

func (a *Advisories) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(a.client), topics)
}
