package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/assessment"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

const CodeInvalidAssessment RejectionCode = "invalid_assessment"

type AssessmentBackbone interface {
	PublishAssessments(ctx context.Context, assessments []*assessmentv1.Assessment) error
}

type AssessmentPolicy struct {
	Gateway                string
	MaxAssessmentsPerBatch int
	Assessment             event.Policy
}

// The fourth sibling: what an agent found when it ran the checks of its policy
// is neither telemetry nor what an asset has, so it travels on a stream of its
// own, bounded in assessments rather than in events or items.
type AssessmentAdmitter struct {
	backbone AssessmentBackbone
	policy   AssessmentPolicy
	metrics  *AssessmentMetrics
	now      func() time.Time
}

type AssessmentOption func(*AssessmentAdmitter)

func WithAssessmentClock(now func() time.Time) AssessmentOption {
	return func(a *AssessmentAdmitter) { a.now = now }
}

func NewAssessmentAdmitter(backbone AssessmentBackbone, policy AssessmentPolicy, metrics *AssessmentMetrics, options ...AssessmentOption) (*AssessmentAdmitter, error) {
	switch {
	case backbone == nil:
		return nil, errors.New("assessment admission needs a backbone")
	case metrics == nil:
		return nil, errors.New("assessment admission needs metrics")
	case policy.Gateway == "":
		return nil, errors.New("assessment admission needs a gateway identity")
	case policy.MaxAssessmentsPerBatch <= 0 || policy.MaxAssessmentsPerBatch > assessment.MaxAssessmentsPerBatch:
		return nil, fmt.Errorf("assessment admission needs a batch ceiling between 1 and %d", assessment.MaxAssessmentsPerBatch)
	}

	admitter := &AssessmentAdmitter{backbone: backbone, policy: policy, metrics: metrics, now: time.Now}
	for _, option := range options {
		option(admitter)
	}
	return admitter, nil
}

func (a *AssessmentAdmitter) Admit(ctx context.Context, identity agentidentity.Identity, tenant string, batch *assessmentv1.AssessmentBatch) (*ingestv1.BatchAck, error) {
	assessments := batch.GetAssessments()
	if len(assessments) == 0 {
		return nil, a.reject(&Rejection{Code: CodeEmptyBatch, Detail: "the batch carries no assessments", EventIndex: -1})
	}
	if len(assessments) > a.policy.MaxAssessmentsPerBatch {
		return nil, a.reject(&Rejection{
			Code:       CodeBatchTooLarge,
			Detail:     fmt.Sprintf("the batch carries %d assessments and the ceiling is %d", len(assessments), a.policy.MaxAssessmentsPerBatch),
			EventIndex: -1,
		})
	}
	if !protocol.Supported(batch.GetProtocolVersion()) {
		return nil, a.reject(&Rejection{
			Code:       CodeUnsupportedProtocol,
			Detail:     fmt.Sprintf("this gateway speaks protocol %d..%d", protocol.MinVersion, protocol.MaxVersion),
			EventIndex: -1,
		})
	}
	if err := identifier(batch.GetBatchId()); err != nil {
		return nil, a.reject(&Rejection{Code: CodeMalformedBatchID, Detail: err.Error(), Field: "batch_id", EventIndex: -1})
	}

	received := a.now().UTC()
	reception := &eventv1.Reception{
		IngestTime: timestamppb.New(received),
		Gateway:    a.policy.Gateway,
		BatchId:    batch.GetBatchId(),
	}

	for index, assessed := range assessments {
		a.stamp(assessed, identity, tenant, reception)
		if err := assessment.Validate(assessed, received, a.policy.Assessment); err != nil {
			return nil, a.reject(&Rejection{
				Code:       CodeInvalidAssessment,
				Detail:     err.Error(),
				Field:      fieldOf(err),
				EventIndex: index,
			})
		}
		a.metrics.observe(received, assessed)
	}

	if err := a.backbone.PublishAssessments(ctx, assessments); err != nil {
		a.metrics.batchUnavailable(len(assessments))
		return nil, fmt.Errorf("%w: %w", ErrBackboneUnavailable, err)
	}

	a.metrics.batchAccepted(len(assessments), a.now().Sub(received))
	return &ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(assessments))}, nil
}

// A host's posture is evidence about that host, so an agent that could place
// its findings under another agent or estate could make a weakened host look
// hardened: identity and tenant are the certificate's and the registry's.
func (a *AssessmentAdmitter) stamp(assessed *assessmentv1.Assessment, identity agentidentity.Identity, tenant string, reception *eventv1.Reception) {
	if assessed.GetOrigin() == nil {
		assessed.Origin = &eventv1.Origin{}
	}
	assessed.Origin.AgentId = identity.AgentID
	assessed.Origin.TenantId = tenant
	assessed.Reception = reception
}

func (a *AssessmentAdmitter) reject(rejection *Rejection) error {
	a.metrics.batchRejected(string(rejection.Code))
	return rejection
}
