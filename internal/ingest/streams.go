package ingest

import (
	"context"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/assessment"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

const CodeMalformedPayload RejectionCode = "malformed_payload"

// One kind of record a gateway admits. What stands in front of a stream is the
// same whatever the records are — the verified certificate, the registry, the
// limiter, the capacity bound and the body ceiling — so a stream only decodes a
// payload, hands it to its admitter, counts what was refused and describes the
// limits its admitter holds a batch to.
type stream interface {
	name() string
	batch() proto.Message
	admit(ctx context.Context, identity agentidentity.Identity, tenant string, payload []byte) (outcome, error)
	rejected(code string)
	describe() *platformv1.Stream
}

// What the gateway knows about a batch, filled as far as it got: a batch
// refused over the third record it carries is still the batch the log names.
type outcome struct {
	batchID         string
	records         int
	acknowledgement *ingestv1.BatchAck
}

type eventStream struct {
	admitter *Admitter
	metrics  *Metrics
}

func (s eventStream) name() string { return "events" }

func (s eventStream) batch() proto.Message { return &ingestv1.EventBatch{} }

func (s eventStream) rejected(code string) { s.metrics.batchRejected(code) }

func (s eventStream) describe() *platformv1.Stream {
	policy := s.admitter.policy
	return &platformv1.Stream{
		Route:              EventsRoute,
		Batch:              fullName(s.batch()),
		Record:             fullName(&eventv1.Event{}),
		SupportedSchema:    &platformv1.VersionRange{Minimum: event.MinSchemaVersion, Maximum: event.MaxSchemaVersion},
		MaxRecordsPerBatch: count(policy.MaxEventsPerBatch),
		MaxRecordBytes:     sendable(event.MaxEventBytes, stamping(&eventv1.Event{}, s.admitter.stamp)),
		MaxAge:             durationpb.New(policy.Event.MaxAge),
		MaxClockSkew:       durationpb.New(policy.Event.MaxClockSkew),
	}
}

func (s eventStream) admit(ctx context.Context, identity agentidentity.Identity, tenant string, payload []byte) (outcome, error) {
	var batch ingestv1.EventBatch
	if err := proto.Unmarshal(payload, &batch); err != nil {
		return outcome{}, refuseMalformed(s)
	}

	carried := outcome{batchID: batch.GetBatchId(), records: len(batch.GetEvents())}
	acknowledgement, err := s.admitter.Admit(ctx, identity, tenant, &batch)
	if err != nil {
		return carried, err
	}
	carried.acknowledgement = acknowledgement
	return carried, nil
}

type inventoryStream struct {
	admitter *InventoryAdmitter
	metrics  *InventoryMetrics
}

func (s inventoryStream) name() string { return "inventory" }

func (s inventoryStream) batch() proto.Message { return &inventoryv1.RecordBatch{} }

func (s inventoryStream) rejected(code string) { s.metrics.batchRejected(code) }

func (s inventoryStream) describe() *platformv1.Stream {
	policy := s.admitter.policy
	return &platformv1.Stream{
		Route:              InventoryRoute,
		Batch:              fullName(s.batch()),
		Record:             fullName(&inventoryv1.Record{}),
		SupportedSchema:    &platformv1.VersionRange{Minimum: inventory.MinSchemaVersion, Maximum: inventory.MaxSchemaVersion},
		MaxRecordsPerBatch: count(policy.MaxRecordsPerBatch),
		MaxRecordBytes:     sendable(inventory.MaxRecordBytes, stamping(&inventoryv1.Record{}, s.admitter.stamp)),
		MaxAge:             durationpb.New(policy.Record.MaxAge),
		MaxClockSkew:       durationpb.New(policy.Record.MaxClockSkew),
		MaxItemsPerRecord:  count(inventory.MaxItemsPerRecord),
		MaxItemsPerBatch:   count(inventory.MaxItemsPerBatch),
	}
}

func (s inventoryStream) admit(ctx context.Context, identity agentidentity.Identity, tenant string, payload []byte) (outcome, error) {
	var batch inventoryv1.RecordBatch
	if err := proto.Unmarshal(payload, &batch); err != nil {
		return outcome{}, refuseMalformed(s)
	}

	carried := outcome{batchID: batch.GetBatchId(), records: len(batch.GetRecords())}
	acknowledgement, err := s.admitter.Admit(ctx, identity, tenant, &batch)
	if err != nil {
		return carried, err
	}
	carried.acknowledgement = acknowledgement
	return carried, nil
}

type statusStream struct {
	admitter *StatusAdmitter
	metrics  *StatusMetrics
}

func (s statusStream) name() string { return "status" }

func (s statusStream) batch() proto.Message { return &agentv1.StatusBatch{} }

func (s statusStream) rejected(code string) { s.metrics.batchRejected(code) }

func (s statusStream) describe() *platformv1.Stream {
	policy := s.admitter.policy
	return &platformv1.Stream{
		Route:              StatusRoute,
		Batch:              fullName(s.batch()),
		Record:             fullName(&agentv1.Status{}),
		SupportedSchema:    &platformv1.VersionRange{Minimum: agentstatus.MinSchemaVersion, Maximum: agentstatus.MaxSchemaVersion},
		MaxRecordsPerBatch: count(policy.MaxReportsPerBatch),
		MaxRecordBytes:     sendable(agentstatus.MaxReportBytes, stamping(&agentv1.Status{}, s.admitter.stamp)),
		MaxAge:             durationpb.New(policy.Report.MaxAge),
		MaxClockSkew:       durationpb.New(policy.Report.MaxClockSkew),
	}
}

func (s statusStream) admit(ctx context.Context, identity agentidentity.Identity, tenant string, payload []byte) (outcome, error) {
	var batch agentv1.StatusBatch
	if err := proto.Unmarshal(payload, &batch); err != nil {
		return outcome{}, refuseMalformed(s)
	}

	carried := outcome{batchID: batch.GetBatchId(), records: len(batch.GetReports())}
	acknowledgement, err := s.admitter.Admit(ctx, identity, tenant, &batch)
	if err != nil {
		return carried, err
	}
	carried.acknowledgement = acknowledgement
	return carried, nil
}

type assessmentStream struct {
	admitter *AssessmentAdmitter
	metrics  *AssessmentMetrics
}

func (s assessmentStream) name() string { return "assessments" }

func (s assessmentStream) batch() proto.Message { return &assessmentv1.AssessmentBatch{} }

func (s assessmentStream) rejected(code string) { s.metrics.batchRejected(code) }

func (s assessmentStream) describe() *platformv1.Stream {
	policy := s.admitter.policy
	return &platformv1.Stream{
		Route:              AssessmentsRoute,
		Batch:              fullName(s.batch()),
		Record:             fullName(&assessmentv1.Assessment{}),
		SupportedSchema:    &platformv1.VersionRange{Minimum: assessment.MinSchemaVersion, Maximum: assessment.MaxSchemaVersion},
		MaxRecordsPerBatch: count(policy.MaxAssessmentsPerBatch),
		MaxRecordBytes:     sendable(assessment.MaxAssessmentBytes, stamping(&assessmentv1.Assessment{}, s.admitter.stamp)),
		MaxAge:             durationpb.New(policy.Assessment.MaxAge),
		MaxClockSkew:       durationpb.New(policy.Assessment.MaxClockSkew),
	}
}

func (s assessmentStream) admit(ctx context.Context, identity agentidentity.Identity, tenant string, payload []byte) (outcome, error) {
	var batch assessmentv1.AssessmentBatch
	if err := proto.Unmarshal(payload, &batch); err != nil {
		return outcome{}, refuseMalformed(s)
	}

	carried := outcome{batchID: batch.GetBatchId(), records: len(batch.GetAssessments())}
	acknowledgement, err := s.admitter.Admit(ctx, identity, tenant, &batch)
	if err != nil {
		return carried, err
	}
	carried.acknowledgement = acknowledgement
	return carried, nil
}

// A payload that does not decode is counted against the route that was reading
// it rather than against the process, so an operator sees which producer is
// sending what this gateway cannot read.
func refuseMalformed(s stream) error {
	s.rejected(string(CodeMalformedPayload))
	return &Rejection{
		Code:       CodeMalformedPayload,
		Detail:     "the batch is not a valid protobuf message",
		EventIndex: -1,
	}
}
