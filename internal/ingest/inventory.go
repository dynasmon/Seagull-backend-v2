package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const CodeInvalidRecord RejectionCode = "invalid_record"

type InventoryBackbone interface {
	PublishInventory(ctx context.Context, records []*inventoryv1.Record) error
}

type InventoryPolicy struct {
	Gateway            string
	MaxRecordsPerBatch int
	Record             event.Policy
}

// The sibling of Admitter, not a second method on it: what an asset has travels
// on a stream of its own, so the two admit against different ceilings, publish
// to different topics and are measured in different units.
type InventoryAdmitter struct {
	backbone InventoryBackbone
	policy   InventoryPolicy
	metrics  *InventoryMetrics
	now      func() time.Time
}

type InventoryOption func(*InventoryAdmitter)

func WithInventoryClock(now func() time.Time) InventoryOption {
	return func(a *InventoryAdmitter) { a.now = now }
}

func NewInventoryAdmitter(backbone InventoryBackbone, policy InventoryPolicy, metrics *InventoryMetrics, options ...InventoryOption) (*InventoryAdmitter, error) {
	if backbone == nil {
		return nil, errors.New("inventory admission needs a backbone")
	}
	if metrics == nil {
		return nil, errors.New("inventory admission needs metrics")
	}
	if policy.Gateway == "" {
		return nil, errors.New("inventory admission needs a gateway identity")
	}
	if policy.MaxRecordsPerBatch <= 0 {
		return nil, errors.New("inventory admission needs a positive batch ceiling")
	}

	admitter := &InventoryAdmitter{backbone: backbone, policy: policy, metrics: metrics, now: time.Now}
	for _, option := range options {
		option(admitter)
	}
	return admitter, nil
}

// Bounded by records and again by the items they carry, because a batch of a
// dozen records is a few kilobytes or a hundred megabytes depending on what an
// asset was observed to have.
func (a *InventoryAdmitter) Admit(ctx context.Context, identity agentidentity.Identity, tenant string, batch *inventoryv1.RecordBatch) (*ingestv1.BatchAck, error) {
	records := batch.GetRecords()
	if len(records) == 0 {
		return nil, a.reject(&Rejection{Code: CodeEmptyBatch, Detail: "the batch carries no records", EventIndex: -1})
	}
	if len(records) > a.policy.MaxRecordsPerBatch {
		return nil, a.reject(&Rejection{
			Code:       CodeBatchTooLarge,
			Detail:     fmt.Sprintf("the batch carries %d records and the ceiling is %d", len(records), a.policy.MaxRecordsPerBatch),
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
	if carried := items(records); carried > inventory.MaxItemsPerBatch {
		return nil, a.reject(&Rejection{
			Code:       CodeBatchTooLarge,
			Detail:     fmt.Sprintf("the batch carries %d items and the ceiling is %d", carried, inventory.MaxItemsPerBatch),
			EventIndex: -1,
		})
	}

	received := a.now().UTC()
	reception := &eventv1.Reception{
		IngestTime: timestamppb.New(received),
		Gateway:    a.policy.Gateway,
		BatchId:    batch.GetBatchId(),
	}

	for index, record := range records {
		a.stamp(record, identity, tenant, reception)
		if err := inventory.Validate(record, received, a.policy.Record); err != nil {
			return nil, a.reject(&Rejection{
				Code:       CodeInvalidRecord,
				Detail:     err.Error(),
				Field:      fieldOf(err),
				EventIndex: index,
			})
		}
		a.metrics.observe(received, record)
	}

	if err := a.backbone.PublishInventory(ctx, records); err != nil {
		a.metrics.batchUnavailable(len(records))
		return nil, fmt.Errorf("%w: %w", ErrBackboneUnavailable, err)
	}

	a.metrics.batchAccepted(len(records), a.now().Sub(received))
	return &ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(records))}, nil
}

// A collector that could place its own records in another estate would undo the
// tenant binding every other record kind is held to, so identity and tenant are
// assigned from the verified certificate and the registry, never merged.
func (a *InventoryAdmitter) stamp(record *inventoryv1.Record, identity agentidentity.Identity, tenant string, reception *eventv1.Reception) {
	if record.GetOrigin() == nil {
		record.Origin = &eventv1.Origin{}
	}
	record.Origin.AgentId = identity.AgentID
	record.Origin.TenantId = tenant
	record.Reception = reception
}

func (a *InventoryAdmitter) reject(rejection *Rejection) error {
	a.metrics.batchRejected(string(rejection.Code))
	return rejection
}

func items(records []*inventoryv1.Record) int {
	carried := 0
	for _, record := range records {
		carried += len(record.GetItems())
	}
	return carried
}
