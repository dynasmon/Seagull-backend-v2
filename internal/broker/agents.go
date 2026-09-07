package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const agentSchema = "seagull.agent.v1.Admission"

type Agents struct {
	client *kgo.Client
	topic  string
}

func NewAgents(config Config) (*Agents, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Agents{client: client, topic: config.Topic}, nil
}

// Keyed by the agent, on a compacted topic, so the log keeps the last thing
// decided about each one and a reader that replays it holds the whole registry
// without reading a relational store.
func (a *Agents) Publish(ctx context.Context, record *agentv1.Admission) error {
	if record.GetAgentId() == "" {
		return errors.New("an admission record is keyed by the agent it is about, and this one names none")
	}
	encoded, err := proto.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode the admission of agent %s: %w", record.GetAgentId(), err)
	}

	written := &kgo.Record{
		Topic: a.topic,
		Key:   []byte(record.GetAgentId()),
		Value: encoded,
		Headers: []kgo.RecordHeader{
			{Key: "content-type", Value: []byte(contentType)},
			{Key: "schema", Value: []byte(agentSchema)},
		},
	}
	if err := a.client.ProduceSync(ctx, written).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", a.topic, err)
	}
	return nil
}

func (a *Agents) Ping(ctx context.Context) error {
	if err := a.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (a *Agents) Close() { a.client.Close() }

func (a *Agents) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(a.client), topics)
}
