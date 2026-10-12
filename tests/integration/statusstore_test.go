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

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/statusstore"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func migratedStatusStore(t *testing.T, address string) *clickhouse.StatusStore {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	migrator, err := clickhouse.NewMigrator(storeSettings(address))
	if err != nil {
		t.Fatalf("build the migrator: %v", err)
	}
	if _, err := migrator.Apply(ctx); err != nil {
		t.Fatalf("apply the schema: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatalf("close the migrator: %v", err)
	}

	store, err := clickhouse.NewStatusStore(storeSettings(address))
	if err != nil {
		t.Fatalf("build the status store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass verification: %v", err)
	}
	return store
}

func received(owner, agentID string, sequence uint64, at time.Time) (*agentv1.Status, statusstore.Row) {
	report := fixtures.Report{AgentID: agentID, Sequence: sequence, At: at.Add(-time.Second)}.Status()
	report.Origin.TenantId = owner
	report.Reception = &eventv1.Reception{IngestTime: timestamppb.New(at), Gateway: "gateway-integration", BatchId: fmt.Sprintf("status-%d", sequence)}
	published, err := proto.Marshal(report)
	if err != nil {
		panic(err)
	}
	return report, statusstore.Project(report, published)
}

func newest(t *testing.T, address string, agents []string, tenants []string) map[string]statusOf {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	held, err := liveness(t, address, 720*time.Hour).Newest(ctx, agents, tenants)
	if err != nil {
		t.Fatalf("read what agents last reported: %v", err)
	}
	read := map[string]statusOf{}
	for agentID, report := range held {
		read[agentID] = statusOf{received: report.Received, report: report.Status, liveness: report.Liveness(time.Now())}
	}
	return read
}

type statusOf struct {
	received time.Time
	report   *agentv1.Status
	liveness agentv1.Liveness
}

// What an agent last said is read for the agents of one page and within the
// tenants the caller holds, the newest by when the platform received it, and
// handed back as the agent sent it.
func TestTheNewestReportOfEachAgentAskedAboutIsReadBackWithinTheCallersTenants(t *testing.T) {
	address := storeAddress(t)
	store := migratedStatusStore(t, address)
	owner, elsewhere := tenant(t), tenant(t)
	talkative, other, silent := agentIdentifier(t), agentIdentifier(t), agentIdentifier(t)

	now := time.Now().UTC().Truncate(time.Millisecond)
	_, first := received(owner, talkative, 1, now.Add(-2*time.Minute))
	latest, second := received(owner, talkative, 2, now.Add(-time.Minute))
	_, foreign := received(elsewhere, other, 1, now.Add(-time.Minute))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Store(ctx, []statusstore.Row{second, first, foreign}); err != nil {
		t.Fatalf("store the reports: %v", err)
	}

	read := newest(t, address, []string{talkative, other, silent}, []string{owner})
	if len(read) != 1 {
		t.Fatalf("read reports of %d agents, and only %s reported within %s", len(read), talkative, owner)
	}
	held := read[talkative]
	if !held.received.Equal(now.Add(-time.Minute)) || !proto.Equal(held.report, latest) {
		t.Fatalf("the newest report reads as received %s with sequence %d", held.received, held.report.GetSequence())
	}
	if held.liveness != agentv1.Liveness_LIVENESS_ACTIVE {
		t.Fatalf("an agent that reported a minute ago is %s", held.liveness)
	}
}

// The platform's clock decides which report is newest: one that says it was
// written later and arrived first never stands in for one received after it.
func TestTheReportReceivedLastIsTheNewestWhateverItsOwnClockSays(t *testing.T) {
	address := storeAddress(t)
	store := migratedStatusStore(t, address)
	owner, agentID := tenant(t), agentIdentifier(t)

	now := time.Now().UTC().Truncate(time.Millisecond)
	_, early := received(owner, agentID, 7, now.Add(-time.Minute))
	early.ReportedAt = now.Add(time.Minute)
	_, late := received(owner, agentID, 8, now)
	late.ReportedAt = now.Add(-time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, row := range []statusstore.Row{late, early} {
		if err := store.Store(ctx, []statusstore.Row{row}); err != nil {
			t.Fatalf("store a report: %v", err)
		}
	}

	if held := newest(t, address, []string{agentID}, []string{owner})[agentID]; held.report.GetSequence() != 8 {
		t.Fatalf("the newest report is sequence %d", held.report.GetSequence())
	}
}

func TestAReportTheGatewayAdmitsIsFoldedAndReadBackAndFoldingItAgainChangesNothing(t *testing.T) {
	addresses := brokers(t)
	address := storeAddress(t)
	store := migratedStatusStore(t, address)
	owner, agentID := tenant(t), agentIdentifier(t)

	topic := temporaryTopic(t, addresses)
	quarantineTopic := temporaryTopic(t, addresses)

	publisher, err := broker.NewStatus(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the status publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	admitter, err := ingest.NewStatusAdmitter(publisher, ingest.StatusPolicy{
		Gateway:            "gateway-integration",
		MaxReportsPerBatch: 16,
		Report:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
	}, ingest.NewStatusMetrics(metrics.New("integration")))
	if err != nil {
		t.Fatalf("build the status admitter: %v", err)
	}

	report := fixtures.Report{AgentID: "claims-to-be-someone-else", Sequence: 3, Condition: agentv1.Status_CONDITION_DEGRADED}.Status()
	admitCtx, cancelAdmit := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelAdmit()
	for range 2 {
		acknowledgement, err := admitter.Admit(admitCtx, agentidentity.Identity{AgentID: agentID}, owner, fixtures.StatusBatch("status-pipeline", proto.Clone(report).(*agentv1.Status)))
		if err != nil || !acknowledgement.GetDurable() {
			t.Fatalf("admit the report: %+v, %v", acknowledgement, err)
		}
	}

	folding, stopFolding := context.WithCancel(context.Background())
	defer stopFolding()

	group := fmt.Sprintf("status-projector-%d", time.Now().UnixNano())
	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      addresses,
		Topic:        topic,
		Group:        group,
		ClientID:     "integration-test",
		MaxRecords:   64,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(metrics.New("integration")),
	})
	if err != nil {
		t.Fatalf("build the consumer: %v", err)
	}
	t.Cleanup(consumer.Close)

	refused, err := broker.NewQuarantine(broker.Config{Brokers: addresses, Topic: quarantineTopic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the quarantine publisher: %v", err)
	}
	t.Cleanup(refused.Close)

	component, err := statusstore.NewProjector(statusstore.ProjectorOptions{
		Source:        statusFetchedBy(consumer),
		Sink:          store,
		Quarantine:    statusQuarantine(refused),
		Metrics:       statusstore.NewMetrics(metrics.New("integration")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  30 * time.Second,
		RetryDelay:    100 * time.Millisecond,
		MaxRetryDelay: time.Second,
	})
	if err != nil {
		t.Fatalf("build the projector: %v", err)
	}

	stopped := make(chan error, 1)
	go func() { stopped <- component.Run(folding) }()

	awaitCommitted(t, addresses, topic, group, 2)

	stopFolding()
	if err := <-stopped; err != nil && !isCancellation(err) {
		t.Fatalf("the projector stopped with %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var current uint64
	if err := inspector(t, address).QueryRow(ctx, "SELECT count() FROM agent_status FINAL WHERE tenant_id = ?", owner).Scan(&current); err != nil || current != 1 {
		t.Fatalf("the store holds %d current reports for one agent: %v", current, err)
	}
	held := newest(t, address, []string{agentID}, []string{owner})[agentID]
	if held.report.GetOrigin().GetAgentId() != agentID || held.report.GetSequence() != 3 ||
		held.report.GetCondition() != agentv1.Status_CONDITION_DEGRADED || held.liveness != agentv1.Liveness_LIVENESS_ACTIVE {
		t.Fatalf("the control plane reads %+v, %s", held.report, held.liveness)
	}
}

type statusSource struct{ consumer *broker.Consumer }

func statusFetchedBy(consumer *broker.Consumer) statusstore.Source {
	return statusSource{consumer: consumer}
}

func (s statusSource) Consume(ctx context.Context, deliver statusstore.Deliver) error {
	return s.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		converted := make([]statusstore.Record, 0, len(records))
		for _, record := range records {
			converted = append(converted, statusstore.Record{Partition: record.Partition, Offset: record.Offset, Key: record.Key, Value: record.Value})
		}
		return deliver(ctx, converted)
	})
}

type statusQuarantinedTo func(ctx context.Context, refused []statusstore.Refused) error

func (q statusQuarantinedTo) Publish(ctx context.Context, refused []statusstore.Refused) error {
	return q(ctx, refused)
}

func statusQuarantine(topic *broker.Quarantine) statusQuarantinedTo {
	return func(ctx context.Context, refused []statusstore.Refused) error {
		converted := make([]broker.Refused, 0, len(refused))
		for _, entry := range refused {
			converted = append(converted, broker.Refused{Key: entry.Key, Value: entry.Value, Reason: entry.Reason, Detail: entry.Detail, Partition: entry.Partition, Offset: entry.Offset})
		}
		return topic.Publish(ctx, converted)
	}
}
