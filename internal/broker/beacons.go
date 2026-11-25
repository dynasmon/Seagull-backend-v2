package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

const beaconSchema = "seagull.platform.v1.GatewayBeacon"

type Beacons struct {
	client *kgo.Client
	topic  string
}

func NewBeacons(config Config) (*Beacons, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Beacons{client: client, topic: config.Topic}, nil
}

// Keyed by the gateway, on a compacted topic, so the log keeps the newest thing
// each gateway said and a reader learns which ones are serving from what it
// hears next.
func (b *Beacons) Announce(ctx context.Context, beacon *platformv1.GatewayBeacon) error {
	if beacon.GetGateway() == "" {
		return errors.New("a beacon is keyed by the gateway that sends it, and this one names none")
	}
	encoded, err := proto.Marshal(beacon)
	if err != nil {
		return fmt.Errorf("encode the beacon of gateway %s: %w", beacon.GetGateway(), err)
	}
	written := &kgo.Record{
		Topic: b.topic,
		Key:   []byte(beacon.GetGateway()),
		Value: encoded,
		Headers: []kgo.RecordHeader{
			{Key: "content-type", Value: []byte(contentType)},
			{Key: "schema", Value: []byte(beaconSchema)},
		},
	}
	if err := b.client.ProduceSync(ctx, written).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", b.topic, err)
	}
	return nil
}

func (b *Beacons) Ping(ctx context.Context) error {
	if err := b.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", named(err))
	}
	return nil
}

func (b *Beacons) Close() { b.client.Close() }

func (b *Beacons) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, b.client, topics)
}
