//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/findingstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

func migratedFindingStore(t *testing.T, address string) *clickhouse.FindingStore {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	migrator, err := clickhouse.NewMigrator(storeSettings(address), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("build the migrator: %v", err)
	}
	if _, err := migrator.Apply(ctx); err != nil {
		t.Fatalf("apply the schema: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatalf("close the migrator: %v", err)
	}

	store, err := clickhouse.NewFindingStore(storeSettings(address))
	if err != nil {
		t.Fatalf("build the finding store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass verification: %v", err)
	}
	return store
}

func keepFindings(t *testing.T, store *clickhouse.FindingStore, records ...*vulnerabilityv1.FindingRecord) {
	t.Helper()

	var (
		findings    []findingstore.FindingRow
		assessments []findingstore.AssessmentRow
	)
	for _, record := range records {
		published, err := proto.Marshal(record)
		if err != nil {
			t.Fatalf("encode a finding record: %v", err)
		}
		switch body := record.GetRecord().(type) {
		case *vulnerabilityv1.FindingRecord_Finding:
			findings = append(findings, findingstore.ProjectFinding(body.Finding, published))
		case *vulnerabilityv1.FindingRecord_Assessment:
			assessments = append(assessments, findingstore.ProjectAssessment(body.Assessment, published))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Store(ctx, findings, assessments); err != nil {
		t.Fatalf("store the finding records: %v", err)
	}
}

type episode struct {
	state    string
	openedAt time.Time
	decided  time.Time
}

func episodesOf(t *testing.T, address, owner, agentID string) []episode {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rows, err := inspector(t, address).Query(ctx, `
		SELECT state, opened_at, decided_at FROM vulnerability_findings FINAL
		WHERE tenant_id = ? AND agent_id = ? ORDER BY decided_at`, owner, agentID)
	if err != nil {
		t.Fatalf("read the findings: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var read []episode
	for rows.Next() {
		var held episode
		if err := rows.Scan(&held.state, &held.openedAt, &held.decided); err != nil {
			t.Fatalf("read a finding: %v", err)
		}
		held.openedAt, held.decided = held.openedAt.UTC(), held.decided.UTC()
		read = append(read, held)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read the findings: %v", err)
	}
	return read
}

func TestAFindingDecidedAgainWhileOpenIsOneRowAndAFixAndAReintroductionAreRowsOfTheirOwn(t *testing.T) {
	address := storeAddress(t)
	store := migratedFindingStore(t, address)
	owner, agentID := tenant(t), agentIdentifier(t)

	day := time.Date(2026, time.November, 1, 6, 0, 0, 0, time.UTC)
	decided := func(state vulnerabilityv1.FindingState, opened time.Time, days int) fixtures.Decision {
		return fixtures.Decision{
			TenantID: owner, AgentID: agentID, State: state, OpenedAt: opened,
			InventoryAsOf:    day.Add(time.Duration(days) * 24 * time.Hour),
			IntelligenceAsOf: day.Add(time.Duration(days)*24*time.Hour - time.Hour),
			DecidedAt:        day.Add(time.Duration(days)*24*time.Hour + time.Minute),
		}
	}
	affected, fixed := vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, vulnerabilityv1.FindingState_FINDING_STATE_FIXED
	reintroduced := vulnerabilityv1.FindingState_FINDING_STATE_REINTRODUCED
	reopened := day.Add(3 * 24 * time.Hour)

	keepFindings(t, store, decided(affected, day, 0).Record())
	keepFindings(t, store, decided(affected, day, 1).Record())
	keepFindings(t, store, decided(affected, day, 0).Record())
	keepFindings(t, store, decided(fixed, day, 2).Record())
	keepFindings(t, store, decided(reintroduced, reopened, 3).Record())
	replayed := decided(reintroduced, reopened, 3)
	replayed.DecidedAt = replayed.DecidedAt.Add(time.Hour)
	keepFindings(t, store, replayed.Record())

	got := episodesOf(t, address, owner, agentID)
	want := []episode{
		{"affected", day, day.Add(24*time.Hour + time.Minute)},
		{"fixed", day, day.Add(2*24*time.Hour + time.Minute)},
		{"reintroduced", reopened, reopened.Add(time.Minute + time.Hour)},
	}
	if len(got) != len(want) {
		t.Fatalf("a finding opened, decided again, decided late, fixed, reintroduced and replayed is stored as %+v, want %+v", got, want)
	}
	for index := range want {
		if got[index].state != want[index].state || !got[index].openedAt.Equal(want[index].openedAt) || !got[index].decided.Equal(want[index].decided) {
			t.Errorf("row %d is %+v, want %+v", index, got[index], want[index])
		}
	}
}

func TestTheStoreHandsBackTheRecordTheMatcherPublished(t *testing.T) {
	address := storeAddress(t)
	store := migratedFindingStore(t, address)
	owner, agentID := tenant(t), agentIdentifier(t)

	record := fixtures.Decision{TenantID: owner, AgentID: agentID}.Record()
	keepFindings(t, store, record)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var (
		body, state, ecosystem, advised, severity string
	)
	if err := inspector(t, address).QueryRow(ctx, `
		SELECT record, state, advised_ecosystem, advised_package, severity_type
		FROM vulnerability_findings FINAL WHERE tenant_id = ? AND agent_id = ?`, owner, agentID,
	).Scan(&body, &state, &ecosystem, &advised, &severity); err != nil {
		t.Fatalf("read the finding back: %v", err)
	}
	var read vulnerabilityv1.FindingRecord
	if err := proto.Unmarshal([]byte(body), &read); err != nil || !proto.Equal(&read, record) {
		t.Fatalf("the store handed back %v (%v), not the record the matcher published", &read, err)
	}
	if state != "affected" || ecosystem != "Debian:12" || advised != "openssl" || severity != "cvss_v3" {
		t.Fatalf("the finding is stored as %s, %s %s, rated %s", state, ecosystem, advised, severity)
	}
}

func TestAnAssessmentIsOneRowPerScopeAndInstantsHoweverOftenItIsDecided(t *testing.T) {
	address := storeAddress(t)
	store := migratedFindingStore(t, address)
	owner, agentID := tenant(t), agentIdentifier(t)

	decision := fixtures.Decision{TenantID: owner, AgentID: agentID, DecidedAt: time.Date(2026, time.November, 8, 6, 0, 0, 0, time.UTC)}
	whole := decision.Assessment(3, 1)
	partial := decision.Assessment(1, 0)
	partial.GetAssessment().Scope = vulnerabilityv1.Assessment_SCOPE_PACKAGES
	again := decision.Assessment(3, 1)
	again.GetAssessment().DecidedAt.Seconds += 60

	keepFindings(t, store, whole, partial)
	keepFindings(t, store, again)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var scopes, opened, unassessed uint64
	if err := inspector(t, address).QueryRow(ctx, `
		SELECT count(), sum(open), sum(unassessed) FROM vulnerability_assessments FINAL
		WHERE tenant_id = ? AND agent_id = ?`, owner, agentID,
	).Scan(&scopes, &opened, &unassessed); err != nil {
		t.Fatalf("read the assessments: %v", err)
	}
	if scopes != 2 || opened != 4 || unassessed != 4 {
		t.Fatalf("a whole and a partial assessment, the whole one decided twice, are %d rows opening %d and leaving %d unassessed", scopes, opened, unassessed)
	}
}

func TestAFindingPublishedTwiceIsKeptOnceAndOneTheContractRefusesIsQuarantined(t *testing.T) {
	addresses := brokers(t)
	address := storeAddress(t)
	store := migratedFindingStore(t, address)
	owner, agentID := tenant(t), agentIdentifier(t)

	topic := temporaryTopic(t, addresses)
	quarantineTopic := temporaryTopic(t, addresses)

	publisher, err := broker.NewFindings(broker.Config{Brokers: addresses, Topic: topic, MaxMessageBytes: temporaryCarriage, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the finding publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	decision := fixtures.Decision{TenantID: owner, AgentID: agentID}
	malformed := fixtures.Decision{TenantID: owner, AgentID: agentID, Vulnerability: "CVE-2024-5535"}.Record()
	malformed.GetFinding().Advised.Ecosystem = "debian:12"

	publishCtx, cancelPublish := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelPublish()
	if err := publisher.Publish(publishCtx, []*vulnerabilityv1.FindingRecord{
		decision.Record(), decision.Assessment(1, 0), malformed, decision.Record(),
	}); err != nil {
		t.Fatalf("publish the finding records: %v", err)
	}

	writing, stopWriting := context.WithCancel(context.Background())
	defer stopWriting()

	group := fmt.Sprintf("finding-writer-%d", time.Now().UnixNano())
	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      addresses,
		Topic:        topic,
		Group:        group,
		ClientID:     "integration-test",
		MaxRecords:   1_000,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(metrics.New("integration")),
	})
	if err != nil {
		t.Fatalf("build the consumer: %v", err)
	}
	t.Cleanup(consumer.Close)

	refused, err := broker.NewQuarantine(broker.Config{Brokers: addresses, Topic: quarantineTopic, MaxMessageBytes: temporaryCarriage, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the quarantine publisher: %v", err)
	}
	t.Cleanup(refused.Close)

	component, err := findingstore.NewWriter(findingstore.WriterOptions{
		Source:        findingsFetchedBy(consumer),
		Sink:          store,
		Quarantine:    findingQuarantine(refused),
		Metrics:       findingstore.NewMetrics(metrics.New("integration")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  30 * time.Second,
		RetryDelay:    100 * time.Millisecond,
		MaxRetryDelay: time.Second,
	})
	if err != nil {
		t.Fatalf("build the writer: %v", err)
	}

	stopped := make(chan error, 1)
	go func() { stopped <- component.Run(writing) }()

	awaitCommitted(t, addresses, topic, group, 4)

	stopWriting()
	if err := <-stopped; err != nil && !isCancellation(err) {
		t.Fatalf("the writer stopped with %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var findings, assessments uint64
	if err := inspector(t, address).QueryRow(ctx, `
		SELECT (SELECT count() FROM vulnerability_findings FINAL WHERE tenant_id = ?),
		       (SELECT count() FROM vulnerability_assessments FINAL WHERE tenant_id = ?)`, owner, owner,
	).Scan(&findings, &assessments); err != nil {
		t.Fatalf("count what was stored: %v", err)
	}
	if findings != 1 || assessments != 1 {
		t.Fatalf("a finding published twice and its assessment are stored as %d findings and %d assessments", findings, assessments)
	}

	reasons := quarantinedReasons(t, addresses, quarantineTopic, 1)
	if len(reasons) != 1 || reasons[0] != findingstore.ReasonContractViolation {
		t.Fatalf("the quarantine holds %v, want the one finding the contract refuses", reasons)
	}
}

func quarantinedReasons(t *testing.T, addresses []string, topic string, expected int) []string {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...), kgo.ConsumeTopics(topic), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	defer client.Close()

	var reasons []string
	deadline := time.Now().Add(30 * time.Second)
	for len(reasons) < expected && time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		client.PollFetches(ctx).EachRecord(func(record *kgo.Record) {
			for _, header := range record.Headers {
				if header.Key == "quarantine-reason" {
					reasons = append(reasons, string(header.Value))
				}
			}
		})
		cancel()
	}
	return reasons
}

type findingSource struct{ consumer *broker.Consumer }

func findingsFetchedBy(consumer *broker.Consumer) findingstore.Source {
	return findingSource{consumer: consumer}
}

func (s findingSource) Consume(ctx context.Context, deliver findingstore.Deliver) error {
	return s.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		converted := make([]findingstore.Record, 0, len(records))
		for _, record := range records {
			converted = append(converted, findingstore.Record{Partition: record.Partition, Offset: record.Offset, Key: record.Key, Value: record.Value})
		}
		return deliver(ctx, converted)
	})
}

type findingQuarantinedTo func(ctx context.Context, refused []findingstore.Refused) error

func (q findingQuarantinedTo) Publish(ctx context.Context, refused []findingstore.Refused) error {
	return q(ctx, refused)
}

func findingQuarantine(topic *broker.Quarantine) findingQuarantinedTo {
	return func(ctx context.Context, refused []findingstore.Refused) error {
		converted := make([]broker.Refused, 0, len(refused))
		for _, entry := range refused {
			converted = append(converted, broker.Refused{Key: entry.Key, Value: entry.Value, Reason: entry.Reason, Detail: entry.Detail, Partition: entry.Partition, Offset: entry.Offset})
		}
		return topic.Publish(ctx, converted)
	}
}
