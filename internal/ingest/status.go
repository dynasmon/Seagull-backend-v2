package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

const CodeInvalidReport RejectionCode = "invalid_report"

type StatusBackbone interface {
	PublishStatus(ctx context.Context, reports []*agentv1.Status) error
}

type StatusPolicy struct {
	Gateway            string
	MaxReportsPerBatch int
	Report             event.Policy
}

// The third sibling, for the same reason the inventory admitter is one: what an
// agent says of itself travels on a stream of its own, so it never waits behind
// telemetry, never makes telemetry wait, and is bounded in reports rather than
// in events.
type StatusAdmitter struct {
	backbone StatusBackbone
	policy   StatusPolicy
	metrics  *StatusMetrics
	now      func() time.Time
}

type StatusOption func(*StatusAdmitter)

func WithStatusClock(now func() time.Time) StatusOption {
	return func(a *StatusAdmitter) { a.now = now }
}

func NewStatusAdmitter(backbone StatusBackbone, policy StatusPolicy, metrics *StatusMetrics, options ...StatusOption) (*StatusAdmitter, error) {
	switch {
	case backbone == nil:
		return nil, errors.New("status admission needs a backbone")
	case metrics == nil:
		return nil, errors.New("status admission needs metrics")
	case policy.Gateway == "":
		return nil, errors.New("status admission needs a gateway identity")
	case policy.MaxReportsPerBatch <= 0 || policy.MaxReportsPerBatch > agentstatus.MaxReportsPerBatch:
		return nil, fmt.Errorf("status admission needs a batch ceiling between 1 and %d", agentstatus.MaxReportsPerBatch)
	}

	admitter := &StatusAdmitter{backbone: backbone, policy: policy, metrics: metrics, now: time.Now}
	for _, option := range options {
		option(admitter)
	}
	return admitter, nil
}

func (a *StatusAdmitter) Admit(ctx context.Context, identity agentidentity.Identity, tenant string, batch *agentv1.StatusBatch) (*ingestv1.BatchAck, error) {
	reports := batch.GetReports()
	if len(reports) == 0 {
		return nil, a.reject(&Rejection{Code: CodeEmptyBatch, Detail: "the batch carries no reports", EventIndex: -1})
	}
	if len(reports) > a.policy.MaxReportsPerBatch {
		return nil, a.reject(&Rejection{
			Code:       CodeBatchTooLarge,
			Detail:     fmt.Sprintf("the batch carries %d reports and the ceiling is %d", len(reports), a.policy.MaxReportsPerBatch),
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

	for index, report := range reports {
		a.stamp(report, identity, tenant, reception)
		if err := agentstatus.Validate(report, received, a.policy.Report); err != nil {
			return nil, a.reject(&Rejection{
				Code:       CodeInvalidReport,
				Detail:     err.Error(),
				Field:      fieldOf(err),
				EventIndex: index,
			})
		}
		a.metrics.observe(received, report)
	}

	if err := a.backbone.PublishStatus(ctx, reports); err != nil {
		a.metrics.batchUnavailable(len(reports))
		return nil, fmt.Errorf("%w: %w", ErrBackboneUnavailable, err)
	}

	a.metrics.batchAccepted(len(reports), a.now().Sub(received))
	return &ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(reports))}, nil
}

// An agent that could report as another, or place its report in another
// estate, would let a copied key speak for a host it was never on, so identity
// and tenant are the certificate's and the registry's, never the report's.
func (a *StatusAdmitter) stamp(report *agentv1.Status, identity agentidentity.Identity, tenant string, reception *eventv1.Reception) {
	if report.GetOrigin() == nil {
		report.Origin = &eventv1.Origin{}
	}
	report.Origin.AgentId = identity.AgentID
	report.Origin.TenantId = tenant
	report.Reception = reception
}

func (a *StatusAdmitter) reject(rejection *Rejection) error {
	a.metrics.batchRejected(string(rejection.Code))
	return rejection
}
