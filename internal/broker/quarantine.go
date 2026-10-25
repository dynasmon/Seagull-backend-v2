package broker

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/twmb/franz-go/pkg/kgo"
)

const maxDetailBytes = 4 << 10

type Refused struct {
	Key       []byte
	Value     []byte
	Reason    string
	Detail    string
	Partition int32
	Offset    int64
}

type Quarantine struct {
	client *kgo.Client
	topic  string
}

func NewQuarantine(config Config) (*Quarantine, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Quarantine{client: client, topic: config.Topic}, nil
}

// The value is the record exactly as it arrived, so it stays replayable. The
// reason and position travel as headers rather than in a second schema that
// would itself have to parse.
func (q *Quarantine) Publish(ctx context.Context, refused []Refused) error {
	if len(refused) == 0 {
		return nil
	}

	records := make([]*kgo.Record, 0, len(refused))
	for _, entry := range refused {
		records = append(records, &kgo.Record{
			Topic: q.topic,
			Key:   entry.Key,
			Value: entry.Value,
			Headers: []kgo.RecordHeader{
				{Key: "quarantine-reason", Value: []byte(entry.Reason)},
				{Key: "quarantine-detail", Value: []byte(bounded(entry.Detail))},
				{Key: "source-partition", Value: []byte(label(entry.Partition))},
				{Key: "source-offset", Value: []byte(fmt.Sprint(entry.Offset))},
			},
		})
	}

	if err := q.client.ProduceSync(ctx, records...).FirstErr(); err != nil {
		return fmt.Errorf("quarantine to %s: %w", q.topic, err)
	}
	return nil
}

func (q *Quarantine) Ping(ctx context.Context) error {
	if err := q.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (q *Quarantine) Close() { q.client.Close() }

// What a refusal says beside the record is bounded, so a quarantine carrying
// its stream's largest batch and its framing always takes the copy.
func bounded(detail string) string {
	if len(detail) <= maxDetailBytes {
		return detail
	}
	cut := maxDetailBytes
	for cut > 0 && !utf8.RuneStart(detail[cut]) {
		cut--
	}
	return detail[:cut]
}
