package broker

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	contentType = "application/x-protobuf"
	schemaName  = "seagull.event.v1.Event"
)

var schemaVersion = strconv.Itoa(event.SchemaVersion)

type Config struct {
	Brokers  []string
	Topic    string
	ClientID string
	Security Security
}

type Publisher struct {
	client *kgo.Client
	topic  string
}

// Records are acknowledged by every in-sync replica before a produce returns,
// and the producer is idempotent: an agent is told its batch is durable only
// once the backbone owns it.
func newProducerClient(config Config) (*kgo.Client, error) {
	if len(config.Brokers) == 0 {
		return nil, errors.New("the backbone needs at least one broker address")
	}
	if config.Topic == "" {
		return nil, errors.New("the backbone needs a topic")
	}

	secured, err := config.Security.options()
	if err != nil {
		return nil, err
	}

	client, err := kgo.NewClient(append([]kgo.Opt{
		kgo.SeedBrokers(config.Brokers...),
		kgo.ClientID(config.ClientID),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.ZstdCompression(), kgo.NoCompression()),
		kgo.ProducerLinger(5 * time.Millisecond),
		kgo.MaxBufferedRecords(200_000),
		kgo.RecordRetries(3),
	}, secured...)...)
	if err != nil {
		return nil, fmt.Errorf("create backbone client: %w", err)
	}
	return client, nil
}

func NewPublisher(config Config) (*Publisher, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Publisher{client: client, topic: config.Topic}, nil
}

func (p *Publisher) PublishEvents(ctx context.Context, events []*eventv1.Event) error {
	if len(events) == 0 {
		return nil
	}

	records, err := encode(p.topic, events)
	if err != nil {
		return err
	}

	if err := p.client.ProduceSync(ctx, records...).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", p.topic, err)
	}
	return nil
}

func encode(topic string, events []*eventv1.Event) ([]*kgo.Record, error) {
	records := make([]*kgo.Record, 0, len(events))
	for _, record := range events {
		encoded, err := proto.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("encode event %s: %w", record.GetEventId(), err)
		}
		records = append(records, &kgo.Record{
			Topic: topic,
			Key:   []byte(record.GetOrigin().GetAgentId()),
			Value: encoded,
			Headers: []kgo.RecordHeader{
				{Key: "content-type", Value: []byte(contentType)},
				{Key: "schema", Value: []byte(schemaName)},
				{Key: "schema-version", Value: []byte(schemaVersion)},
			},
		})
	}
	return records, nil
}

func (p *Publisher) Ping(ctx context.Context) error {
	if err := p.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (p *Publisher) Close() { p.client.Close() }
