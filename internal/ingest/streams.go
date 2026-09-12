package ingest

import (
	"context"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const CodeMalformedPayload RejectionCode = "malformed_payload"

// One kind of record a gateway admits. What stands in front of a stream is the
// same whatever the records are — the verified certificate, the registry, the
// limiter, the capacity bound and the body ceiling — so a stream only decodes a
// payload, hands it to its admitter and counts what was refused.
type stream interface {
	name() string
	admit(ctx context.Context, identity agentidentity.Identity, tenant string, payload []byte) (outcome, error)
	rejected(code string)
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

func (s eventStream) rejected(code string) { s.metrics.batchRejected(code) }

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

func (s inventoryStream) rejected(code string) { s.metrics.batchRejected(code) }

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
