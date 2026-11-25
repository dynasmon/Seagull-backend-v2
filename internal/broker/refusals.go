package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const refusalSchema = "seagull.agent.v1.Refusal"

type Refusals struct {
	client *kgo.Client
	topic  string
}

func NewRefusals(config Config) (*Refusals, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Refusals{client: client, topic: config.Topic}, nil
}

// Keyed by the agent, so the refusals of one agent are read in the order its
// gateways published them.
func (r *Refusals) PublishRefusals(ctx context.Context, refused []*agentv1.Refusal) error {
	records := make([]*kgo.Record, 0, len(refused))
	for _, one := range refused {
		if one.GetAgentId() == "" {
			return errors.New("a refusal is keyed by the agent it is about, and this one names none")
		}
		encoded, err := proto.Marshal(one)
		if err != nil {
			return fmt.Errorf("encode the refusals of agent %s: %w", one.GetAgentId(), err)
		}
		records = append(records, &kgo.Record{
			Topic: r.topic,
			Key:   []byte(one.GetAgentId()),
			Value: encoded,
			Headers: []kgo.RecordHeader{
				{Key: "content-type", Value: []byte(contentType)},
				{Key: "schema", Value: []byte(refusalSchema)},
			},
		})
	}
	if err := r.client.ProduceSync(ctx, records...).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", r.topic, err)
	}
	return nil
}

func (r *Refusals) Ping(ctx context.Context) error {
	if err := r.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", named(err))
	}
	return nil
}

func (r *Refusals) Close() { r.client.Close() }
