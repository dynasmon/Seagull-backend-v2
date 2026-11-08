//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/finding"
	"github.com/dynasmon/Seagull-backend-v2/internal/findingstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventorystore"
	"github.com/dynasmon/Seagull-backend-v2/internal/matching"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

type matchedFrom struct{ consumer *broker.Consumer }

func (m matchedFrom) Consume(ctx context.Context, deliver matching.Deliver) error {
	return m.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		converted := make([]matching.Record, 0, len(records))
		for _, record := range records {
			converted = append(converted, matching.Record{Topic: record.Topic, Partition: record.Partition, Offset: record.Offset, Value: record.Value})
		}
		return deliver(ctx, converted)
	})
}

func debianSystem(owner, agentID string, at time.Time) *inventoryv1.Record {
	return &inventoryv1.Record{
		RecordId:      "inv-system-" + agentID,
		SchemaVersion: inventory.SchemaVersion,
		Kind:          inventoryv1.Kind_KIND_OPERATING_SYSTEM,
		Mode:          inventoryv1.Mode_MODE_SNAPSHOT,
		CollectedAt:   timestamppb.New(at),
		Origin:        &eventv1.Origin{AgentId: agentID, TenantId: owner},
		Collection:    &eventv1.Collection{Collector: "syscollector", Source: "os-release"},
		Reception:     &eventv1.Reception{IngestTime: timestamppb.New(at), Gateway: "gateway-integration", BatchId: "batch-system"},
		Items: []*inventoryv1.Item{{Body: &inventoryv1.Item_OperatingSystem{OperatingSystem: &inventoryv1.OperatingSystem{
			Name: "Debian GNU/Linux", Version: "12", Platform: "debian", Codename: "bookworm", Family: "debian",
		}}}},
	}
}

func newestDecision(t *testing.T, address, owner, agentID string, want vulnerabilityv1.FindingState) *vulnerabilityv1.Finding {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var body string
		err := inspector(t, address).QueryRow(ctx, `SELECT record FROM vulnerability_findings FINAL WHERE tenant_id = ? AND agent_id = ?
			ORDER BY inventory_as_of DESC, intelligence_as_of DESC, decided_at DESC LIMIT 1`, owner, agentID).Scan(&body)
		cancel()
		var record vulnerabilityv1.FindingRecord
		if err == nil && proto.Unmarshal([]byte(body), &record) == nil && record.GetFinding().GetState() == want {
			return record.GetFinding()
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s finding about agent %s reached the store before the deadline (last read: %v, %v)", want, agentID, record.GetFinding().GetState(), err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// The whole path the card asks for, with nothing stubbed between its ends: an
// inventory scan reaches its store through its owner, the matcher waits for
// the owner, decides from the stores and publishes, and the writer keeps the
// decision; an upgrade past the fix then closes what the first scan opened.
func TestAScanOfAVulnerablePackageBecomesAFindingAndAnUpgradeFixesIt(t *testing.T) {
	addresses := brokers(t)
	address := storeAddress(t)
	inventories := migratedInventoryStore(t, address)
	advisories := migratedAdvisoryStore(t, address)
	findings := migratedFindingStore(t, address)
	reader := matchingReaderOf(t, address)
	owner, agentID := tenant(t), agentIdentifier(t)
	source := "openssl-" + owned(t)
	stamp := time.Now().UnixNano()
	projectorGroup, writerGroup, matcherGroup := fmt.Sprintf("inventory-projector-%d", stamp), fmt.Sprintf("finding-writer-%d", stamp), fmt.Sprintf("vulnerability-matcher-%d", stamp)

	now := time.Now().UTC().Truncate(time.Millisecond)
	advisory := version("DSA-"+owned(t), source, now.Add(-time.Hour), 1, "2.0-1")
	advisory.Upstream = []string{"CVE-2026-4242"}
	hold(t, advisories, advised(advisory), &vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Sync{Sync: &vulnerabilityv1.FeedSync{
		Source: "osv", Feed: "Debian", CheckedAt: timestamppb.New(now), Outcome: vulnerabilityv1.FeedSync_OUTCOME_COMPLETE, SyncedAt: timestamppb.New(now),
	}}})

	inventoryTopic, advisoryTopic, findingTopic := temporaryTopic(t, addresses), temporaryTopic(t, addresses), temporaryTopic(t, addresses)
	publisher, err := broker.NewInventory(broker.Config{Brokers: addresses, Topic: inventoryTopic, MaxMessageBytes: temporaryCarriage, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the inventory publisher: %v", err)
	}
	t.Cleanup(publisher.Close)
	scan := func(at time.Time, installed string) {
		t.Helper()
		packages := fixtures.PackageScan{RecordID: fmt.Sprintf("inv-%d", at.UnixMilli()), AgentID: agentID, At: at, Packages: []fixtures.Installed{
			{Name: "libssl3", Version: installed, Architecture: "amd64", Manager: "dpkg", Source: source},
		}}.Record()
		packages.Origin.TenantId = owner
		packages.Reception = &eventv1.Reception{IngestTime: timestamppb.New(at), Gateway: "gateway-integration", BatchId: "batch-packages"}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := publisher.PublishInventory(ctx, []*inventoryv1.Record{debianSystem(owner, agentID, at), packages}); err != nil {
			t.Fatalf("publish the scan: %v", err)
		}
	}

	running, stop := context.WithCancel(context.Background())
	defer stop()
	stopped := make(chan error, 3)
	consumerOf := func(group string, topics ...string) *broker.Consumer {
		consumer, err := broker.NewConsumer(broker.ConsumerConfig{
			Brokers: addresses, Topics: topics, Group: group, ClientID: "integration-test",
			MaxRecords: 64, FetchMaxWait: 200 * time.Millisecond, Metrics: broker.NewConsumerMetrics(metrics.New("integration")),
		})
		if err != nil {
			t.Fatalf("build the consumer of %s: %v", group, err)
		}
		t.Cleanup(consumer.Close)
		return consumer
	}
	refused, err := broker.NewQuarantine(broker.Config{Brokers: addresses, Topic: temporaryTopic(t, addresses), MaxMessageBytes: temporaryCarriage, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the quarantine publisher: %v", err)
	}
	t.Cleanup(refused.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	projector, err := inventorystore.NewProjector(inventorystore.ProjectorOptions{
		Source: foldedBy(consumerOf(projectorGroup, inventoryTopic)), Sink: inventories, Quarantine: quarantineInventoryTo(refused),
		Metrics: inventorystore.NewMetrics(metrics.New("integration")), Logger: logger,
		WriteTimeout: 30 * time.Second, RetryDelay: 100 * time.Millisecond, MaxRetryDelay: time.Second,
	})
	if err != nil {
		t.Fatalf("build the projector: %v", err)
	}
	writer, err := findingstore.NewWriter(findingstore.WriterOptions{
		Source: findingsFetchedBy(consumerOf(writerGroup, findingTopic)), Sink: findings, Quarantine: findingQuarantine(refused),
		Metrics: findingstore.NewMetrics(metrics.New("integration")), Logger: logger,
		WriteTimeout: 30 * time.Second, RetryDelay: 100 * time.Millisecond, MaxRetryDelay: time.Second,
	})
	if err != nil {
		t.Fatalf("build the writer: %v", err)
	}
	positions := positionsOf(t, addresses)
	decisions, err := broker.NewFindings(broker.Config{Brokers: addresses, Topic: findingTopic, MaxMessageBytes: temporaryCarriage, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the findings publisher: %v", err)
	}
	t.Cleanup(decisions.Close)
	matcher, err := matching.NewMatcher(matching.Options{
		Source: matchedFrom{consumer: consumerOf(matcherGroup, inventoryTopic, advisoryTopic)}, Positions: positions,
		Inventory: reader, Intelligence: reader, Findings: reader, Publisher: decisions,
		Owners: matching.Owners{
			Inventory:  matching.Owner{Topic: inventoryTopic, Group: projectorGroup},
			Advisories: matching.Owner{Topic: advisoryTopic, Group: fmt.Sprintf("advisory-writer-%d", stamp)},
			Findings:   matching.Owner{Topic: findingTopic, Group: writerGroup},
		},
		Policy: finding.Policy{Freshness: 48 * time.Hour}, SettleDelay: 50 * time.Millisecond,
		RetryDelay: 100 * time.Millisecond, MaxRetryDelay: time.Second,
		Metrics: matching.NewMetrics(metrics.New("integration")), Logger: logger, Now: time.Now,
	})
	if err != nil {
		t.Fatalf("build the matcher: %v", err)
	}
	for _, component := range []interface{ Run(context.Context) error }{projector, writer, matcher} {
		go func() { stopped <- component.Run(running) }()
	}

	first := now.Add(-10 * time.Minute)
	scan(first, "1.0-1")
	affected := newestDecision(t, address, owner, agentID, vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED)
	if affected.GetVulnerabilityId() != "CVE-2026-4242" || affected.GetFix() != "2.0-1" || !affected.GetOpenedAt().AsTime().Equal(first) ||
		len(affected.GetCitations()) != 1 || affected.GetCitations()[0].GetAdvisoryId() != advisory.Id {
		t.Fatalf("the scan was decided as %v", affected)
	}

	scan(now, "2.0-1")
	fixed := newestDecision(t, address, owner, agentID, vulnerabilityv1.FindingState_FINDING_STATE_FIXED)
	if !fixed.GetOpenedAt().AsTime().Equal(first) || fixed.GetFix() != "2.0-1" {
		t.Fatalf("the upgrade was decided as %v, and it closes the episode opened at %s", fixed, first)
	}

	stop()
	for range 3 {
		if err := <-stopped; err != nil && !isCancellation(err) {
			t.Errorf("a component stopped with %v", err)
		}
	}
}
