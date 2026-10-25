//go:build integration

package integration_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventorystore"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func shippedInventory(t *testing.T, addresses []string) (broker.Topic, *broker.Inventory) {
	t.Helper()

	topic := declaredTopic(t, addresses, 3, 48*time.Hour)
	topic.MaxMessageBytes = shippedTopology().Inventory.MaxMessageBytes
	provisioned(t, addresses, topic)

	publisher, err := broker.NewInventory(broker.Config{
		Brokers: addresses, Topic: topic.Name, MaxMessageBytes: topic.MaxMessageBytes, ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build the inventory publisher: %v", err)
	}
	t.Cleanup(publisher.Close)
	return topic, publisher
}

func inventoryAdmitter(t *testing.T, backbone ingest.InventoryBackbone, options ...ingest.InventoryOption) *ingest.InventoryAdmitter {
	t.Helper()

	admitter, err := ingest.NewInventoryAdmitter(backbone, ingest.InventoryPolicy{
		Gateway:            "gateway-integration",
		MaxRecordsPerBatch: 16,
		Record:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
	}, ingest.NewInventoryMetrics(metrics.New("integration")), options...)
	if err != nil {
		t.Fatalf("build the inventory admitter: %v", err)
	}
	return admitter
}

func TestTenThousandPackagesAreMadeDurableAndFoldedIntoTheAsset(t *testing.T) {
	addresses := brokers(t)
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	topic, publisher := shippedInventory(t, addresses)

	widest := fixtures.PackageScan{
		RecordID: "inv-widest-01",
		AgentID:  "web-01",
		At:       time.Now().UTC().Truncate(time.Millisecond),
		Packages: fixtures.DebianPackages(inventory.MaxItemsPerRecord),
	}.Record()
	if size := proto.Size(widest); size <= 1<<20 {
		t.Fatalf("the widest package list encodes to %d bytes, which a backbone carried before any ceiling was declared", size)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	acknowledgement, err := inventoryAdmitter(t, publisher).Admit(ctx, agentidentity.Identity{AgentID: "web-01"}, owner,
		fixtures.InventoryBatch("batch-widest", widest))
	if err != nil {
		t.Fatalf("ten thousand packages were answered %v, and an agent retries an unavailable backbone forever", err)
	}
	if !acknowledgement.GetDurable() {
		t.Fatal("the batch was acknowledged without being made durable")
	}

	quarantine := declaredTopic(t, addresses, 1, 48*time.Hour)
	quarantine.MaxMessageBytes = shippedTopology().InventoryQuarantine.MaxMessageBytes
	provisioned(t, addresses, quarantine)
	refused, err := broker.NewQuarantine(broker.Config{
		Brokers: addresses, Topic: quarantine.Name, MaxMessageBytes: quarantine.MaxMessageBytes, ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build the quarantine publisher: %v", err)
	}
	t.Cleanup(refused.Close)

	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      addresses,
		Topic:        topic.Name,
		Group:        fmt.Sprintf("inventory-projector-%d", time.Now().UnixNano()),
		ClientID:     "integration-test",
		MaxRecords:   64,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(metrics.New("integration")),
	})
	if err != nil {
		t.Fatalf("build the consumer: %v", err)
	}
	t.Cleanup(consumer.Close)

	component, err := inventorystore.NewProjector(inventorystore.ProjectorOptions{
		Source:        foldedBy(consumer),
		Sink:          store,
		Quarantine:    quarantineInventoryTo(refused),
		Metrics:       inventorystore.NewMetrics(metrics.New("integration")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  30 * time.Second,
		RetryDelay:    100 * time.Millisecond,
		MaxRetryDelay: time.Second,
	})
	if err != nil {
		t.Fatalf("build the projector: %v", err)
	}

	folding, stopFolding := context.WithCancel(context.Background())
	defer stopFolding()
	stopped := make(chan error, 1)
	go func() { stopped <- component.Run(folding) }()

	waitForItems(t, address, owner, inventory.MaxItemsPerRecord)

	stopFolding()
	if err := <-stopped; err != nil && !isCancellation(err) {
		t.Fatalf("the projector stopped with %v", err)
	}
}

func TestAnInventoryRecordWeighingTheCeilingIsMadeDurableAndOneByteMoreIsRefused(t *testing.T) {
	addresses := brokers(t)
	topic, publisher := shippedInventory(t, addresses)

	widestAgent := strings.Repeat("a", event.MaxAgentIDLength)
	received := time.Now().UTC().Truncate(time.Second)
	admitter := inventoryAdmitter(t, publisher, ingest.WithInventoryClock(func() time.Time { return received }))
	weighing := func(size int) *inventoryv1.Record {
		snapshot := &inventoryv1.Record{
			RecordId:      "inv-ceiling-01",
			SchemaVersion: inventory.SchemaVersion,
			Kind:          inventoryv1.Kind_KIND_PROCESS,
			Mode:          inventoryv1.Mode_MODE_SNAPSHOT,
			CollectedAt:   timestamppb.New(received.Add(-time.Minute)),
			Origin:        &eventv1.Origin{AgentId: widestAgent, TenantId: "acme"},
			Collection:    &eventv1.Collection{Collector: "processes"},
			Reception:     &eventv1.Reception{IngestTime: timestamppb.New(received), Gateway: "gateway-integration", BatchId: "batch-ceiling"},
		}
		if !fixtures.Weigh(snapshot, size) {
			t.Fatalf("no process snapshot encodes to %d bytes", size)
		}
		return snapshot
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	identity := agentidentity.Identity{AgentID: widestAgent}

	if _, err := admitter.Admit(ctx, identity, "acme", fixtures.InventoryBatch("batch-ceiling", weighing(inventory.MaxRecordBytes))); err != nil {
		t.Fatalf("a record weighing the ceiling under the widest key was answered %v", err)
	}
	if held := consume(t, addresses, topic.Name, 1); len(held[0].Value) != inventory.MaxRecordBytes {
		t.Fatalf("the backbone holds a record of %d bytes", len(held[0].Value))
	}

	_, err := admitter.Admit(ctx, identity, "acme", fixtures.InventoryBatch("batch-ceiling", weighing(inventory.MaxRecordBytes+1)))
	var rejection *ingest.Rejection
	if !errors.As(err, &rejection) || rejection.Code != ingest.CodeInvalidRecord || rejection.EventIndex != 0 {
		t.Fatalf("a record one byte above the ceiling was answered %v rather than refused by its position", err)
	}
}
