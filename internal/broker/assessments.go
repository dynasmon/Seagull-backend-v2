package broker

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/assessment"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

const assessmentSchema = "seagull.assessment.v1.Assessment"

var assessmentSchemaVersion = strconv.Itoa(assessment.SchemaVersion)

// Where what an agent found running the checks of its policy goes when it
// leaves the gateway: a topic of its own, because an assessment is neither an
// event nor what an asset has, and is read by a projector of its own.
type Assessments struct {
	client *kgo.Client
	topic  string
}

func NewAssessments(config Config) (*Assessments, error) {
	client, err := newProducerClient(config)
	if err != nil {
		return nil, err
	}
	return &Assessments{client: client, topic: config.Topic}, nil
}

// Keyed by the agent that made them, so the assessments of one host are read
// in the order they arrived. The topic keeps every one of them for its
// retention rather than the newest: what a posture was over time is what an
// agent kept them for.
func (a *Assessments) PublishAssessments(ctx context.Context, assessments []*assessmentv1.Assessment) error {
	if len(assessments) == 0 {
		return nil
	}

	written := make([]*kgo.Record, 0, len(assessments))
	for _, assessed := range assessments {
		agentID := assessed.GetOrigin().GetAgentId()
		if agentID == "" {
			return errors.New("an assessment is keyed by the agent that made it, and this one names none")
		}
		encoded, err := proto.Marshal(assessed)
		if err != nil {
			return fmt.Errorf("encode assessment %s of agent %s: %w", assessed.GetAssessmentId(), agentID, err)
		}
		written = append(written, &kgo.Record{
			Topic: a.topic,
			Key:   []byte(agentID),
			Value: encoded,
			Headers: []kgo.RecordHeader{
				{Key: "content-type", Value: []byte(contentType)},
				{Key: "schema", Value: []byte(assessmentSchema)},
				{Key: "schema-version", Value: []byte(assessmentSchemaVersion)},
			},
		})
	}

	if err := a.client.ProduceSync(ctx, written...).FirstErr(); err != nil {
		return fmt.Errorf("publish to %s: %w", a.topic, err)
	}
	return nil
}

func (a *Assessments) Ping(ctx context.Context) error {
	if err := a.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (a *Assessments) Close() { a.client.Close() }

func (a *Assessments) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(a.client), topics)
}
