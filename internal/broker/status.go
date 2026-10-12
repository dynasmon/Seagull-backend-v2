package broker

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const statusSchema = "seagull.agent.v1.Status"

var statusSchemaVersion = strconv.Itoa(agentstatus.SchemaVersion)

// Where what an agent says of itself goes when it leaves the gateway: a topic
// of its own, so a fleet reporting every minute never stands in the way of the
// telemetry it describes.
type Status struct {
	client *kgo.Client
	topic  string
}

func NewStatus(config Config) (*Status, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Status{client: client, topic: config.Topic}, nil
}

// Keyed by the agent, on a compacted topic, because a report stands on its own
// and the newest one of each agent is what anybody reads: the log keeps that
// one for a reader that starts long after it was written, and the reports of
// one agent are read in the order they arrived.
func (s *Status) PublishStatus(ctx context.Context, reports []*agentv1.Status) error {
	if len(reports) == 0 {
		return nil
	}

	written := make([]*kgo.Record, 0, len(reports))
	for _, report := range reports {
		agentID := report.GetOrigin().GetAgentId()
		if agentID == "" {
			return errors.New("a status report is keyed by the agent it is about, and this one names none")
		}
		encoded, err := proto.Marshal(report)
		if err != nil {
			return fmt.Errorf("encode the status report %d of agent %s: %w", report.GetSequence(), agentID, err)
		}
		written = append(written, &kgo.Record{
			Topic: s.topic,
			Key:   []byte(agentID),
			Value: encoded,
			Headers: []kgo.RecordHeader{
				{Key: "content-type", Value: []byte(contentType)},
				{Key: "schema", Value: []byte(statusSchema)},
				{Key: "schema-version", Value: []byte(statusSchemaVersion)},
			},
		})
	}

	if err := s.client.ProduceSync(ctx, written...).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", s.topic, err)
	}
	return nil
}

func (s *Status) Ping(ctx context.Context) error {
	if err := s.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (s *Status) Close() { s.client.Close() }

func (s *Status) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(s.client), topics)
}
