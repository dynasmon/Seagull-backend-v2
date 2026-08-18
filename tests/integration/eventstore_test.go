//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	chgo "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	storeDatabase = "seagull"
	storeUser     = "seagull"
)

func storeAddress(t *testing.T) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("SEAGULL_TEST_EVENT_STORE"))
	if value == "" {
		t.Skip("set SEAGULL_TEST_EVENT_STORE to run the event store integration suite")
	}
	return value
}

func storeSettings(address string) clickhouse.Config {
	return clickhouse.Config{
		Address:  address,
		Database: storeDatabase,
		User:     storeUser,
		Timeout:  30 * time.Second,
	}
}

// The schema arrives by command, as in a deployment; the writer only verifies.
func migratedStore(t *testing.T, address string) *clickhouse.Store {
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

	store, err := clickhouse.NewStore(storeSettings(address))
	if err != nil {
		t.Fatalf("build the store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass verification: %v", err)
	}
	return store
}

// Assertions read the database directly: asking the writer whether it wrote the
// rows would prove nothing.
func inspector(t *testing.T, address string) driver.Conn {
	t.Helper()

	connection, err := chgo.Open(&chgo.Options{
		Addr: []string{address},
		Auth: chgo.Auth{Database: storeDatabase, Username: storeUser},
	})
	if err != nil {
		t.Fatalf("connect to the store: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

// Tests share one table, so each one owns a tenant nobody else writes under.
func tenant(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("tenant-%d", time.Now().UnixNano())
}

func TestTheStoreKeepsEveryFieldTheContractCarries(t *testing.T) {
	address := storeAddress(t)
	store := migratedStore(t, address)
	owner := tenant(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	at := time.Date(2026, time.August, 17, 10, 30, 0, 0, time.UTC)
	record := fixtures.SSHAuthentication{
		EventID:  "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
		AgentID:  "web-01",
		Hostname: "web-01.acme.example",
		At:       at,
		Username: "root",
		Sequence: 42,
	}.Event()
	record.Origin.TenantId = owner
	record.Reception = &eventv1.Reception{
		IngestTime: timestamppb.New(at),
		Gateway:    "ingest-gateway",
		BatchId:    "batch-1",
	}

	if err := store.Store(ctx, []eventstore.Row{eventstore.Project(record)}); err != nil {
		t.Fatalf("write the event: %v", err)
	}

	var (
		eventID, eventClass, agentID, hostname, collector    string
		activity, outcome, reason, method, username, service string
		transport, rawRecord                                 string
		schemaVersion                                        uint32
		sourcePort, destinationPort                          uint16
		sequence                                             uint64
		eventTime, ingestTime                                time.Time
	)
	err := inspector(t, address).QueryRow(ctx, `
		SELECT event_id, schema_version, event_class, event_time, ingest_time,
		       agent_id, host_hostname, collector, sequence,
		       auth_activity, auth_outcome, auth_outcome_reason, auth_method,
		       auth_user_name, auth_service_name, auth_source_port,
		       auth_destination_port, auth_transport, auth_raw_record
		FROM security_events FINAL WHERE tenant_id = ?`, owner,
	).Scan(&eventID, &schemaVersion, &eventClass, &eventTime, &ingestTime,
		&agentID, &hostname, &collector, &sequence,
		&activity, &outcome, &reason, &method,
		&username, &service, &sourcePort, &destinationPort, &transport, &rawRecord)
	if err != nil {
		t.Fatalf("read the event back: %v", err)
	}

	for _, field := range []struct {
		name string
		got  any
		want any
	}{
		{"event_id", eventID, record.GetEventId()},
		{"schema_version", schemaVersion, record.GetSchemaVersion()},
		{"event_class", eventClass, "authentication"},
		{"agent_id", agentID, "web-01"},
		{"host_hostname", hostname, "web-01.acme.example"},
		{"collector", collector, "ssh.authlog"},
		{"sequence", sequence, uint64(42)},
		{"auth_activity", activity, "logon"},
		{"auth_outcome", outcome, "failure"},
		{"auth_outcome_reason", reason, "failed_password"},
		{"auth_method", method, "password"},
		{"auth_user_name", username, "root"},
		{"auth_service_name", service, "sshd"},
		{"auth_source_port", sourcePort, uint16(54321)},
		{"auth_destination_port", destinationPort, uint16(22)},
		{"auth_transport", transport, "tcp"},
		{"auth_raw_record", rawRecord, record.GetAuthentication().GetRawRecord()},
	} {
		if field.got != field.want {
			t.Errorf("%s came back as %v, want %v", field.name, field.got, field.want)
		}
	}
	if !eventTime.Equal(at) {
		t.Errorf("event_time came back as %s, want %s", eventTime, at)
	}
	if !ingestTime.Equal(at) {
		t.Errorf("ingest_time came back as %s, want %s", ingestTime, at)
	}
}

func TestAReplayedBatchLeavesOneEvent(t *testing.T) {
	address := storeAddress(t)
	store := migratedStore(t, address)
	owner := tenant(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	record := fixtures.SSHAuthentication{
		EventID: "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
		At:      time.Date(2026, time.August, 17, 11, 0, 0, 0, time.UTC),
	}.Event()
	record.Origin.TenantId = owner
	rows := []eventstore.Row{eventstore.Project(record)}

	for attempt := range 3 {
		if err := store.Store(ctx, rows); err != nil {
			t.Fatalf("write attempt %d: %v", attempt+1, err)
		}
	}

	var deduplicated, written uint64
	inspect := inspector(t, address)
	if err := inspect.QueryRow(ctx,
		"SELECT count() FROM security_events FINAL WHERE tenant_id = ?", owner).Scan(&deduplicated); err != nil {
		t.Fatalf("count the deduplicated rows: %v", err)
	}
	if deduplicated != 1 {
		t.Fatalf("three writes of one event left %d rows, want 1", deduplicated)
	}

	if err := inspect.QueryRow(ctx,
		"SELECT count() FROM security_events WHERE tenant_id = ?", owner).Scan(&written); err != nil {
		t.Fatalf("count the written rows: %v", err)
	}
	if written < 1 {
		t.Fatalf("the event was not written at all")
	}
	t.Logf("three writes left %d parts before a merge, and %d event after FINAL", written, deduplicated)
}

func TestAPoisonRecordIsQuarantinedAndTheRestOfTheBatchIsStored(t *testing.T) {
	addresses := brokers(t)
	address := storeAddress(t)
	store := migratedStore(t, address)
	owner := tenant(t)

	quarantineTopic := temporaryTopic(t, addresses)
	refused, err := broker.NewQuarantine(broker.Config{
		Brokers:  addresses,
		Topic:    quarantineTopic,
		ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build the quarantine publisher: %v", err)
	}
	t.Cleanup(refused.Close)

	good := fixtures.SSHAuthentication{
		EventID: "cccccccc-3333-4333-8333-cccccccccccc",
		At:      time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC),
	}.Event()
	good.Origin.TenantId = owner
	encoded, err := proto.Marshal(good)
	if err != nil {
		t.Fatalf("encode the event: %v", err)
	}
	poison := []byte("this never came from a seagull agent")

	writer, err := eventstore.NewWriter(eventstore.WriterOptions{
		Source: batchOnce{records: []eventstore.Record{
			{Partition: 0, Offset: 11, Key: []byte("web-01"), Value: poison},
			{Partition: 0, Offset: 12, Key: []byte("web-01"), Value: encoded},
		}},
		Sink:          store,
		Quarantine:    quarantineTo(refused),
		Metrics:       eventstore.NewMetrics(metrics.New("integration")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  30 * time.Second,
		RetryDelay:    100 * time.Millisecond,
		MaxRetryDelay: time.Second,
	})
	if err != nil {
		t.Fatalf("build the writer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := writer.Run(ctx); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	var stored uint64
	if err := inspector(t, address).QueryRow(ctx,
		"SELECT count() FROM security_events FINAL WHERE tenant_id = ?", owner).Scan(&stored); err != nil {
		t.Fatalf("count the stored events: %v", err)
	}
	if stored != 1 {
		t.Fatalf("the batch left %d events in the store, want the one that was well formed", stored)
	}

	quarantined := consume(t, addresses, quarantineTopic, 1)
	if got := quarantined[0].Value; string(got) != string(poison) {
		t.Fatalf("the quarantined record was rewritten on its way out: %q", got)
	}
	if got := header(quarantined[0], "quarantine-reason"); got != eventstore.ReasonUndecodable {
		t.Errorf("quarantine-reason is %q, want %q", got, eventstore.ReasonUndecodable)
	}
	if header(quarantined[0], "quarantine-detail") == "" {
		t.Error("quarantine-detail says nothing about why the record was refused")
	}
	if got := header(quarantined[0], "source-offset"); got != "11" {
		t.Errorf("source-offset is %q, want the offset the record came from", got)
	}
}

func TestAWriterRefusesToStartAgainstAnUnmigratedStore(t *testing.T) {
	address := storeAddress(t)

	settings := storeSettings(address)
	settings.Database = "system"

	store, err := clickhouse.NewStore(settings)
	if err != nil {
		t.Fatalf("build the store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := store.VerifySchema(ctx); err == nil {
		t.Fatal("a store with no schema of ours reported itself ready to be written to")
	}
}

// Mirrors cmd/event-writer, which a test may not import, so this suite can drive
// the real writer against the real store.
type batchOnce struct{ records []eventstore.Record }

func (b batchOnce) Consume(ctx context.Context, deliver eventstore.Deliver) error {
	return deliver(ctx, b.records)
}

type quarantineOf func(ctx context.Context, refused []eventstore.Refused) error

func (q quarantineOf) Publish(ctx context.Context, refused []eventstore.Refused) error {
	return q(ctx, refused)
}

func quarantineTo(topic *broker.Quarantine) quarantineOf {
	return func(ctx context.Context, refused []eventstore.Refused) error {
		converted := make([]broker.Refused, 0, len(refused))
		for _, entry := range refused {
			converted = append(converted, broker.Refused{
				Key:       entry.Key,
				Value:     entry.Value,
				Reason:    entry.Reason,
				Detail:    entry.Detail,
				Partition: entry.Partition,
				Offset:    entry.Offset,
			})
		}
		return topic.Publish(ctx, converted)
	}
}

func fetchedBy(consumer *broker.Consumer) eventstore.Source {
	return backboneSource{consumer: consumer}
}

type backboneSource struct{ consumer *broker.Consumer }

func (b backboneSource) Consume(ctx context.Context, deliver eventstore.Deliver) error {
	return b.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		converted := make([]eventstore.Record, 0, len(records))
		for _, record := range records {
			converted = append(converted, eventstore.Record{
				Partition: record.Partition,
				Offset:    record.Offset,
				Key:       record.Key,
				Value:     record.Value,
			})
		}
		return deliver(ctx, converted)
	})
}
