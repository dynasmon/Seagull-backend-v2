package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const agentFindingSchema = "seagull.agent.v1.Finding"

type AgentFindings struct {
	client *kgo.Client
	topic  string
}

func NewAgentFindings(config Config) (*AgentFindings, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &AgentFindings{client: client, topic: config.Topic}, nil
}

// Keyed by the agent a decision is about, so one agent's decisions are read in
// the order they were made, and answered only once every one of them is durable.
func (a *AgentFindings) Publish(ctx context.Context, decided []*agentv1.Finding) error {
	records := make([]*kgo.Record, 0, len(decided))
	for _, finding := range decided {
		if finding.GetAgentId() == "" {
			return errors.New("a finding is keyed by the agent it is about, and this one names none")
		}
		encoded, err := proto.Marshal(finding)
		if err != nil {
			return fmt.Errorf("encode finding %s of agent %s: %w", finding.GetFindingId(), finding.GetAgentId(), err)
		}
		records = append(records, &kgo.Record{
			Topic: a.topic,
			Key:   []byte(finding.GetAgentId()),
			Value: encoded,
			Headers: []kgo.RecordHeader{
				{Key: "content-type", Value: []byte(contentType)},
				{Key: "schema", Value: []byte(agentFindingSchema)},
			},
		})
	}
	if len(records) == 0 {
		return nil
	}
	if err := a.client.ProduceSync(ctx, records...).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", a.topic, err)
	}
	return nil
}

func (a *AgentFindings) Ping(ctx context.Context) error {
	if err := a.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (a *AgentFindings) Close() { a.client.Close() }

func (a *AgentFindings) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, a.client, topics)
}
