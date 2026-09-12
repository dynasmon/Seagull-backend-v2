package broker

import (
	"context"
	"fmt"
	"strconv"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const inventorySchema = "seagull.inventory.v1.Record"

var inventorySchemaVersion = strconv.Itoa(inventory.SchemaVersion)

// Where what an asset was observed to have goes when it leaves the gateway.
//
// A stream of its own rather than a class of event: an estate reports orders of
// magnitude more package observations than authentication events, and a shared
// topic would make the lag of every consumer of telemetry a function of how
// many packages the fleet has installed.
type Inventory struct {
	client *kgo.Client
	topic  string
}

func NewInventory(config Config) (*Inventory, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Inventory{client: client, topic: config.Topic}, nil
}

// Keyed by the asset the records are about, so that every scan of one agent is
// read in the order it was written. Which of two scans is the newer one is what
// decides whether an item is still installed, and records of one asset spread
// over two partitions would not agree on the answer.
func (i *Inventory) PublishInventory(ctx context.Context, records []*inventoryv1.Record) error {
	if len(records) == 0 {
		return nil
	}

	written := make([]*kgo.Record, 0, len(records))
	for _, observed := range records {
		encoded, err := proto.Marshal(observed)
		if err != nil {
			return fmt.Errorf("encode inventory record %s: %w", observed.GetRecordId(), err)
		}
		written = append(written, &kgo.Record{
			Topic: i.topic,
			Key:   []byte(observed.GetOrigin().GetAgentId()),
			Value: encoded,
			Headers: []kgo.RecordHeader{
				{Key: "content-type", Value: []byte(contentType)},
				{Key: "schema", Value: []byte(inventorySchema)},
				{Key: "schema-version", Value: []byte(inventorySchemaVersion)},
			},
		})
	}

	if err := i.client.ProduceSync(ctx, written...).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", i.topic, err)
	}
	return nil
}

func (i *Inventory) Ping(ctx context.Context) error {
	if err := i.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (i *Inventory) Close() { i.client.Close() }

func (i *Inventory) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(i.client), topics)
}
