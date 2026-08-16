package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	"github.com/dynasmon/Seagull-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-v2/internal/event"
	"github.com/dynasmon/Seagull-v2/internal/protocol"
)

type RejectionCode string

const (
	CodeEmptyBatch          RejectionCode = "empty_batch"
	CodeBatchTooLarge       RejectionCode = "batch_too_large"
	CodeMalformedBatchID    RejectionCode = "malformed_batch_id"
	CodeUnsupportedProtocol RejectionCode = "unsupported_protocol_version"
	CodeInvalidEvent        RejectionCode = "invalid_event"
)

type Rejection struct {
	Code       RejectionCode
	Detail     string
	Field      string
	EventIndex int
}

func (r *Rejection) Error() string {
	if r.Field == "" {
		return fmt.Sprintf("%s: %s", r.Code, r.Detail)
	}
	return fmt.Sprintf("%s: event %d: %s", r.Code, r.EventIndex, r.Detail)
}

var ErrBackboneUnavailable = errors.New("the event backbone did not accept the batch")

type Backbone interface {
	PublishEvents(ctx context.Context, events []*eventv1.Event) error
}

type Policy struct {
	Gateway           string
	TenantID          string
	MaxEventsPerBatch int
	Event             event.Policy
}

type Admitter struct {
	backbone Backbone
	policy   Policy
	metrics  *Metrics
	now      func() time.Time
}

type Option func(*Admitter)

func WithClock(now func() time.Time) Option {
	return func(a *Admitter) { a.now = now }
}

func NewAdmitter(backbone Backbone, policy Policy, metrics *Metrics, options ...Option) (*Admitter, error) {
	if backbone == nil {
		return nil, errors.New("admission needs a backbone")
	}
	if metrics == nil {
		return nil, errors.New("admission needs metrics")
	}
	if policy.Gateway == "" || policy.TenantID == "" {
		return nil, errors.New("admission needs a gateway and tenant identity")
	}
	if policy.MaxEventsPerBatch <= 0 {
		return nil, errors.New("admission needs a positive batch ceiling")
	}

	admitter := &Admitter{backbone: backbone, policy: policy, metrics: metrics, now: time.Now}
	for _, option := range options {
		option(admitter)
	}
	return admitter, nil
}

func (a *Admitter) Admit(ctx context.Context, identity agentidentity.Identity, batch *ingestv1.EventBatch) (*ingestv1.BatchAck, error) {
	events := batch.GetEvents()
	if len(events) == 0 {
		return nil, a.reject(&Rejection{Code: CodeEmptyBatch, Detail: "the batch carries no events", EventIndex: -1})
	}
	if len(events) > a.policy.MaxEventsPerBatch {
		return nil, a.reject(&Rejection{
			Code:       CodeBatchTooLarge,
			Detail:     fmt.Sprintf("the batch carries %d events and the ceiling is %d", len(events), a.policy.MaxEventsPerBatch),
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

	for index, record := range events {
		a.stamp(record, identity, reception)
		if err := event.Validate(record, received, a.policy.Event); err != nil {
			return nil, a.reject(&Rejection{
				Code:       CodeInvalidEvent,
				Detail:     err.Error(),
				Field:      fieldOf(err),
				EventIndex: index,
			})
		}
		a.metrics.observeLag(received, record)
	}

	if err := a.backbone.PublishEvents(ctx, events); err != nil {
		a.metrics.batchUnavailable(len(events))
		return nil, fmt.Errorf("%w: %w", ErrBackboneUnavailable, err)
	}

	a.metrics.batchAccepted(len(events), a.now().Sub(received))
	return &ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(events))}, nil
}

// Identity and reception are assigned, never merged: whatever a producer put in
// these fields is replaced by what the platform observed.
func (a *Admitter) stamp(record *eventv1.Event, identity agentidentity.Identity, reception *eventv1.Reception) {
	if record.GetOrigin() == nil {
		record.Origin = &eventv1.Origin{}
	}
	record.Origin.AgentId = identity.AgentID
	record.Origin.TenantId = a.policy.TenantID
	record.Reception = reception
}

func (a *Admitter) reject(rejection *Rejection) error {
	a.metrics.batchRejected(string(rejection.Code))
	return rejection
}

func fieldOf(err error) string {
	var violation *event.Violation
	if errors.As(err, &violation) {
		return violation.Field
	}
	return ""
}

func identifier(value string) error {
	if value == "" {
		return errors.New("is required")
	}
	if len(value) > event.MaxBatchIDLength {
		return fmt.Errorf("is longer than %d bytes", event.MaxBatchIDLength)
	}
	if !event.ValidIdentifier(value) {
		return errors.New("is not a usable identifier")
	}
	return nil
}
