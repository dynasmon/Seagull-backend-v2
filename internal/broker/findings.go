package broker

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/finding"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

const findingSchema = "seagull.vulnerability.v1.FindingRecord"

var findingSchemaVersion = strconv.Itoa(finding.SchemaVersion)

// Where the platform's decisions about vulnerable packages go when they leave
// the process that made them.
type Findings struct {
	client *kgo.Client
	topic  string
}

func NewFindings(config Config) (*Findings, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Findings{client: client, topic: config.Topic}, nil
}

// Keyed by the agent a record is about, so one asset's decisions land on one
// partition in the order they were made, and an assessment after the findings
// it decided: a reader that sees the assessment has already seen what it
// covered.
func (f *Findings) Publish(ctx context.Context, records []*vulnerabilityv1.FindingRecord) error {
	if len(records) == 0 {
		return nil
	}

	written := make([]*kgo.Record, 0, len(records))
	for _, entry := range records {
		key, err := findingKey(entry)
		if err != nil {
			return err
		}
		encoded, err := proto.Marshal(entry)
		if err != nil {
			return fmt.Errorf("encode a finding record of agent %s: %w", key, err)
		}
		written = append(written, &kgo.Record{
			Topic: f.topic,
			Key:   key,
			Value: encoded,
			Headers: []kgo.RecordHeader{
				{Key: "content-type", Value: []byte(contentType)},
				{Key: "schema", Value: []byte(findingSchema)},
				{Key: "schema-version", Value: []byte(findingSchemaVersion)},
			},
		})
	}

	if err := f.client.ProduceSync(ctx, written...).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", f.topic, err)
	}
	return nil
}

func findingKey(record *vulnerabilityv1.FindingRecord) ([]byte, error) {
	var agent string
	switch body := record.GetRecord().(type) {
	case *vulnerabilityv1.FindingRecord_Finding:
		agent = body.Finding.GetAgentId()
	case *vulnerabilityv1.FindingRecord_Assessment:
		agent = body.Assessment.GetAgentId()
	default:
		return nil, errors.New("a finding record carries neither a finding nor an assessment")
	}
	if agent == "" {
		return nil, errors.New("a finding record is keyed by the agent it is about, and this one names none")
	}
	return []byte(agent), nil
}

func (f *Findings) Ping(ctx context.Context) error {
	if err := f.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (f *Findings) Close() { f.client.Close() }

func (f *Findings) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, f.client, topics)
}
