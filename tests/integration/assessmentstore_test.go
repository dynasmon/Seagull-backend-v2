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
	"github.com/dynasmon/Seagull-backend-v2/internal/assessmentstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func migratedAssessmentStore(t *testing.T, address string) *clickhouse.AssessmentStore {
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

	store, err := clickhouse.NewAssessmentStore(storeSettings(address))
	if err != nil {
		t.Fatalf("build the assessment store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass verification: %v", err)
	}
	return store
}

func assessedOn(owner, agentID, id string, revision uint64, at, arrived time.Time) (*assessmentv1.Assessment, assessmentstore.Row) {
	assessed := fixtures.Posture{AssessmentID: id, AgentID: agentID, Revision: revision, At: at}.Assessment()
	assessed.Origin.TenantId = owner
	assessed.Reception = &eventv1.Reception{IngestTime: timestamppb.New(arrived), Gateway: "gateway-integration", BatchId: "assessment-" + id}
	published, err := proto.Marshal(assessed)
	if err != nil {
		panic(err)
	}
	return assessed, assessmentstore.Project(assessed, published)
}

func postures(t *testing.T, store *clickhouse.AssessmentStore, agents, tenants []string) map[string]*assessmentv1.Assessment {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	held, err := store.Postures(ctx, agents, tenants)
	if err != nil {
		t.Fatalf("read the postures of agents: %v", err)
	}
	return held
}

// The posture of an agent is its newest assessment by when the agent made it,
// read for the agents asked about and within the tenants the caller holds, and
// every assessment it made stays readable beside it.
func TestThePostureOfEachAgentAskedAboutIsItsNewestAssessmentWithinTheCallersTenants(t *testing.T) {
	address := storeAddress(t)
	store := migratedAssessmentStore(t, address)
	owner, elsewhere := tenant(t), tenant(t)
	assessing, other, never := agentIdentifier(t), agentIdentifier(t), agentIdentifier(t)

	now := time.Now().UTC().Truncate(time.Millisecond)
	_, first := assessedOn(owner, assessing, "asm-first-0001", 3, now.Add(-2*time.Hour), now.Add(-time.Minute))
	latest, second := assessedOn(owner, assessing, "asm-second-0002", 4, now.Add(-time.Hour), now.Add(-2*time.Minute))
	_, foreign := assessedOn(elsewhere, other, "asm-foreign-0003", 1, now.Add(-time.Minute), now)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Store(ctx, []assessmentstore.Row{second, first, foreign}); err != nil {
		t.Fatalf("store the assessments: %v", err)
	}

	read := postures(t, store, []string{assessing, other, never}, []string{owner})
	if len(read) != 1 || !proto.Equal(read[assessing], latest) {
		t.Fatalf("the postures read are %v, and only %s assessed within %s, last under revision 4", read, assessing, owner)
	}

	var kept uint64
	if err := inspector(t, address).QueryRow(ctx, "SELECT count() FROM agent_assessments FINAL WHERE tenant_id = ? AND agent_id = ?", owner, assessing).Scan(&kept); err != nil || kept != 2 {
		t.Fatalf("the store keeps %d assessments of an agent that made two: %v", kept, err)
	}
}

func TestAnAssessmentTheGatewayAdmitsIsKeptOnceWhateverTimesItIsPublished(t *testing.T) {
	addresses := brokers(t)
	address := storeAddress(t)
	store := migratedAssessmentStore(t, address)
	owner, agentID := tenant(t), agentIdentifier(t)

	topic := temporaryTopic(t, addresses)
	quarantineTopic := temporaryTopic(t, addresses)

	publisher, err := broker.NewAssessments(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the assessment publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	admitter, err := ingest.NewAssessmentAdmitter(publisher, ingest.AssessmentPolicy{
		Gateway:                "gateway-integration",
		MaxAssessmentsPerBatch: 16,
		Assessment:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 720 * time.Hour},
	}, ingest.NewAssessmentMetrics(metrics.New("integration")))
	if err != nil {
		t.Fatalf("build the assessment admitter: %v", err)
	}

	assessed := fixtures.Posture{AssessmentID: "asm-pipeline-0001", AgentID: "claims-to-be-someone-else", Revision: 5}.Assessment()
	admitCtx, cancelAdmit := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelAdmit()
	for attempt := range 2 {
		acknowledgement, err := admitter.Admit(admitCtx, agentidentity.Identity{AgentID: agentID}, owner,
			fixtures.AssessmentBatch(fmt.Sprintf("assessment-pipeline-%d", attempt), proto.Clone(assessed).(*assessmentv1.Assessment)))
		if err != nil || !acknowledgement.GetDurable() {
			t.Fatalf("admit the assessment: %+v, %v", acknowledgement, err)
		}
	}

	folding, stopFolding := context.WithCancel(context.Background())
	defer stopFolding()

	group := fmt.Sprintf("assessment-projector-%d", time.Now().UnixNano())
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

	component, err := assessmentstore.NewProjector(assessmentstore.ProjectorOptions{
		Source:        assessmentsFetchedBy(consumer),
		Sink:          store,
		Quarantine:    assessmentQuarantine(refused),
		Metrics:       assessmentstore.NewMetrics(metrics.New("integration")),
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
	var kept uint64
	if err := inspector(t, address).QueryRow(ctx, "SELECT count() FROM agent_assessments FINAL WHERE tenant_id = ?", owner).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("the store keeps %d assessments of one published twice: %v", kept, err)
	}
	held := postures(t, store, []string{agentID}, []string{owner})[agentID]
	if held.GetOrigin().GetAgentId() != agentID || held.GetPolicyRevision() != 5 || len(held.GetResults()) != 3 ||
		held.GetResults()[0].GetOutcome() != assessmentv1.Outcome_OUTCOME_FAIL {
		t.Fatalf("the control plane reads the posture %+v", held)
	}
}

type assessmentSource struct{ consumer *broker.Consumer }

func assessmentsFetchedBy(consumer *broker.Consumer) assessmentstore.Source {
	return assessmentSource{consumer: consumer}
}

func (s assessmentSource) Consume(ctx context.Context, deliver assessmentstore.Deliver) error {
	return s.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		converted := make([]assessmentstore.Record, 0, len(records))
		for _, record := range records {
			converted = append(converted, assessmentstore.Record{Partition: record.Partition, Offset: record.Offset, Key: record.Key, Value: record.Value})
		}
		return deliver(ctx, converted)
	})
}

type assessmentQuarantinedTo func(ctx context.Context, refused []assessmentstore.Refused) error

func (q assessmentQuarantinedTo) Publish(ctx context.Context, refused []assessmentstore.Refused) error {
	return q(ctx, refused)
}

func assessmentQuarantine(topic *broker.Quarantine) assessmentQuarantinedTo {
	return func(ctx context.Context, refused []assessmentstore.Refused) error {
		converted := make([]broker.Refused, 0, len(refused))
		for _, entry := range refused {
			converted = append(converted, broker.Refused{Key: entry.Key, Value: entry.Value, Reason: entry.Reason, Detail: entry.Detail, Partition: entry.Partition, Offset: entry.Offset})
		}
		return topic.Publish(ctx, converted)
	}
}
