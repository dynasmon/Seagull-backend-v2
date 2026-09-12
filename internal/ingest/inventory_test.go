package ingest_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

type recordingInventory struct {
	published [][]*inventoryv1.Record
	failure   error
}

func (r *recordingInventory) PublishInventory(_ context.Context, records []*inventoryv1.Record) error {
	if r.failure != nil {
		return r.failure
	}
	r.published = append(r.published, records)
	return nil
}

func (r *recordingInventory) last() []*inventoryv1.Record {
	if len(r.published) == 0 {
		return nil
	}
	return r.published[len(r.published)-1]
}

func newInventoryAdmitter(t *testing.T, backbone ingest.InventoryBackbone) *ingest.InventoryAdmitter {
	t.Helper()
	admitter, err := ingest.NewInventoryAdmitter(
		backbone,
		ingest.InventoryPolicy{
			Gateway:            "gateway-a",
			MaxRecordsPerBatch: 4,
			Record:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
		},
		ingest.NewInventoryMetrics(metrics.New("test")),
		ingest.WithInventoryClock(func() time.Time { return admissionClock }),
	)
	if err != nil {
		t.Fatalf("build inventory admitter: %v", err)
	}
	return admitter
}

func scan() *inventoryv1.Record {
	return fixtures.PackageScan{At: admissionClock.Add(-time.Minute)}.Record()
}

func crowded(t *testing.T, items int) *inventoryv1.Record {
	t.Helper()
	installed := make([]fixtures.Installed, items)
	for index := range installed {
		installed[index] = fixtures.Installed{Name: "pkg", Version: "1", Architecture: "amd64", Manager: "dpkg"}
	}
	return fixtures.PackageScan{At: admissionClock.Add(-time.Minute), Packages: installed}.Record()
}

func TestAdmittedInventoryBatchIsAcknowledgedAsDurable(t *testing.T) {
	backbone := &recordingInventory{}
	admitter := newInventoryAdmitter(t, backbone)

	acknowledgement, err := admitter.Admit(context.Background(), identity(), "acme", fixtures.InventoryBatch("batch-1", scan(), scan()))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}

	if !acknowledgement.GetAccepted() || !acknowledgement.GetDurable() {
		t.Fatalf("an admitted batch must be acknowledged as durable: %+v", acknowledgement)
	}
	if acknowledgement.GetReceived() != 2 {
		t.Fatalf("expected 2 received records, got %d", acknowledgement.GetReceived())
	}
	if len(backbone.last()) != 2 {
		t.Fatalf("expected 2 published records, got %d", len(backbone.last()))
	}
}

func TestClaimedIdentityAndTenantAreReplacedOnEveryRecordOfTheBatch(t *testing.T) {
	backbone := &recordingInventory{}
	admitter := newInventoryAdmitter(t, backbone)

	impersonating := scan()
	impersonating.Origin.AgentId = "domain-controller"
	impersonating.Origin.TenantId = "someone-else"
	claimingNothing := scan()
	claimingNothing.Origin = nil
	forged := scan()
	forged.Reception = &eventv1.Reception{Gateway: "not-a-gateway", BatchId: "not-this-batch"}

	batch := fixtures.InventoryBatch("batch-7", impersonating, claimingNothing, forged)
	if _, err := admitter.Admit(context.Background(), identity(), "globex", batch); err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}

	for index, published := range backbone.last() {
		if published.GetOrigin().GetAgentId() != "web-01" {
			t.Errorf("record %d kept the claimed agent %q", index, published.GetOrigin().GetAgentId())
		}
		if published.GetOrigin().GetTenantId() != "globex" {
			t.Errorf("record %d is in tenant %q and the registry placed the agent in globex", index, published.GetOrigin().GetTenantId())
		}
		if published.GetReception().GetGateway() != "gateway-a" || published.GetReception().GetBatchId() != "batch-7" {
			t.Errorf("record %d kept a reception the producer wrote: %+v", index, published.GetReception())
		}
		if !published.GetReception().GetIngestTime().AsTime().Equal(admissionClock) {
			t.Errorf("record %d was not stamped by the platform clock: %s", index, published.GetReception().GetIngestTime().AsTime())
		}
	}
}

func TestAnInventoryBatchWithNoTenantToStampIsNeverPublished(t *testing.T) {
	backbone := &recordingInventory{}
	admitter := newInventoryAdmitter(t, backbone)

	if _, err := admitter.Admit(context.Background(), identity(), "", fixtures.InventoryBatch("batch-1", scan())); err == nil {
		t.Fatal("a batch was admitted with no tenant decided for its agent")
	}
	if len(backbone.published) != 0 {
		t.Fatal("a record whose tenant nobody decided reached the backbone")
	}
}

func TestInventoryTheBackboneRefusedIsNeverAcknowledged(t *testing.T) {
	backbone := &recordingInventory{failure: errors.New("no leader for partition")}
	admitter := newInventoryAdmitter(t, backbone)

	acknowledgement, err := admitter.Admit(context.Background(), identity(), "acme", fixtures.InventoryBatch("batch-1", scan()))

	if acknowledgement != nil {
		t.Fatalf("a batch that was not made durable must not be acknowledged: %+v", acknowledgement)
	}
	if !errors.Is(err, ingest.ErrBackboneUnavailable) {
		t.Fatalf("expected an unavailable backbone, got %v", err)
	}
}

func TestAnEmptyInventoryBatchIsRefused(t *testing.T) {
	admitter := newInventoryAdmitter(t, &recordingInventory{})

	_, err := admitter.Admit(context.Background(), identity(), "acme", fixtures.InventoryBatch("batch-1"))

	if code := rejectionOf(t, err).Code; code != ingest.CodeEmptyBatch {
		t.Fatalf("unexpected code %q", code)
	}
}

// Two ceilings, because a batch of a dozen records is a few kilobytes or a
// hundred megabytes depending on what the asset was observed to have.
func TestAnInventoryBatchIsBoundedByRecordsAndByItems(t *testing.T) {
	for name, batch := range map[string]*inventoryv1.RecordBatch{
		"records": fixtures.InventoryBatch("batch-1", scan(), scan(), scan(), scan(), scan()),
		"items": fixtures.InventoryBatch("batch-1",
			crowded(t, inventory.MaxItemsPerRecord),
			crowded(t, inventory.MaxItemsPerRecord),
			crowded(t, inventory.MaxItemsPerBatch-2*inventory.MaxItemsPerRecord+1)),
	} {
		t.Run(name, func(t *testing.T) {
			backbone := &recordingInventory{}
			admitter := newInventoryAdmitter(t, backbone)

			_, err := admitter.Admit(context.Background(), identity(), "acme", batch)

			if code := rejectionOf(t, err).Code; code != ingest.CodeBatchTooLarge {
				t.Fatalf("unexpected code %q", code)
			}
			if len(backbone.published) != 0 {
				t.Fatal("an oversized batch reached the backbone")
			}
		})
	}
}

func TestAnInventoryBatchIdentifierIsRequiredAndTheProtocolIsBounded(t *testing.T) {
	admitter := newInventoryAdmitter(t, &recordingInventory{})

	batch := fixtures.InventoryBatch("", scan())
	if code := rejectionOf(t, admit(t, admitter, batch)).Code; code != ingest.CodeMalformedBatchID {
		t.Fatalf("unexpected code %q", code)
	}

	unsupported := fixtures.InventoryBatch("batch-1", scan())
	unsupported.ProtocolVersion = 99
	if code := rejectionOf(t, admit(t, admitter, unsupported)).Code; code != ingest.CodeUnsupportedProtocol {
		t.Fatalf("unexpected code %q", code)
	}
}

func TestAnInvalidInventoryRecordNamesItsPositionAndField(t *testing.T) {
	backbone := &recordingInventory{}
	admitter := newInventoryAdmitter(t, backbone)

	broken := fixtures.PackageScan{
		At:       admissionClock.Add(-time.Minute),
		Packages: []fixtures.Installed{{Name: strings.Repeat("p", inventory.MaxNameLength+1), Version: "1"}},
	}.Record()

	_, err := admitter.Admit(context.Background(), identity(), "acme", fixtures.InventoryBatch("batch-1", scan(), broken))

	rejection := rejectionOf(t, err)
	if rejection.Code != ingest.CodeInvalidRecord {
		t.Fatalf("unexpected code %q", rejection.Code)
	}
	if rejection.EventIndex != 1 {
		t.Fatalf("expected the offending record index, got %d", rejection.EventIndex)
	}
	if rejection.Field != "items[0].package.name" {
		t.Fatalf("expected the offending field, got %q", rejection.Field)
	}
	if len(backbone.published) != 0 {
		t.Fatal("a batch holding an invalid record reached the backbone")
	}
}

func TestTheInventoryAdmitterRefusesAnIncompletePolicy(t *testing.T) {
	instruments := ingest.NewInventoryMetrics(metrics.New("test"))

	for name, policy := range map[string]ingest.InventoryPolicy{
		"no gateway": {MaxRecordsPerBatch: 1},
		"no ceiling": {Gateway: "gateway-a"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ingest.NewInventoryAdmitter(&recordingInventory{}, policy, instruments); err == nil {
				t.Fatal("expected the admitter to refuse the policy")
			}
		})
	}
}

func admit(t *testing.T, admitter *ingest.InventoryAdmitter, batch *inventoryv1.RecordBatch) error {
	t.Helper()
	_, err := admitter.Admit(context.Background(), identity(), "acme", batch)
	return err
}
