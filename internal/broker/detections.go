package broker

import (
	"context"
	"fmt"
	"strconv"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

const detectionSchema = "seagull.detection.v1.Detection"

var detectionSchemaVersion = strconv.Itoa(detection.SchemaVersion)

// Where a detection goes when it leaves the process that made it.
//
// The engine does not write to a store, and nothing that stores a detection
// reads a rule: they are two consumers of one topic, which is what keeps the
// shape of an alert table out of the thing that decides what an alert is about.
type Detections struct {
	client *kgo.Client
	topic  string
}

func NewDetections(config Config) (*Detections, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Detections{client: client, topic: config.Topic}, nil
}

// Keyed by the agent the detection is about, as telemetry is, so that everything
// the platform records about one agent stays on one partition. A later stage
// that has to hold state per agent can then read this topic alongside the event
// stream without shuffling either of them.
//
// A detection names itself the same way every time it is decided, so a batch
// published twice because it was retried is rewritten by whatever materialises
// it rather than counted twice.
func (d *Detections) Publish(ctx context.Context, detections []*detectionv1.Detection) error {
	if len(detections) == 0 {
		return nil
	}

	records := make([]*kgo.Record, 0, len(detections))
	for _, made := range detections {
		encoded, err := proto.Marshal(made)
		if err != nil {
			return fmt.Errorf("encode detection %s: %w", made.GetDetectionId(), err)
		}
		records = append(records, &kgo.Record{
			Topic: d.topic,
			Key:   []byte(made.GetOrigin().GetAgentId()),
			Value: encoded,
			Headers: []kgo.RecordHeader{
				{Key: "content-type", Value: []byte(contentType)},
				{Key: "schema", Value: []byte(detectionSchema)},
				{Key: "schema-version", Value: []byte(detectionSchemaVersion)},
			},
		})
	}

	if err := d.client.ProduceSync(ctx, records...).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", d.topic, err)
	}
	return nil
}

func (d *Detections) Ping(ctx context.Context) error {
	if err := d.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (d *Detections) Close() { d.client.Close() }
