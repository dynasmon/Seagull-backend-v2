//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/audit"
	"github.com/dynasmon/Seagull-backend-v2/internal/auditstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

// Every chain starts at the first event of its tenant, so a test reading a chain
// owns the store it reads: a chain another run left behind would be where this
// one continues from.
func ownAuditStore(t *testing.T, address string) (*clickhouse.AuditStore, driver.Conn) {
	t.Helper()
	database, connection := freshDatabase(t, address)
	settings := settingsFor(address, database)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	migrator, err := clickhouse.NewMigrator(settings, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("build the migrator: %v", err)
	}
	if _, err := migrator.Apply(ctx); err != nil {
		t.Fatalf("apply the schema: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatalf("close the migrator: %v", err)
	}

	store, err := clickhouse.NewAuditStore(settings)
	if err != nil {
		t.Fatalf("build the audit store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass verification: %v", err)
	}
	return store, connection
}

func auditEvent(id, tenant string) *auditv1.Event {
	return &auditv1.Event{
		SchemaVersion: audit.SchemaVersion,
		EventId:       id,
		TenantId:      tenant,
		OccurredAt:    timestamppb.New(time.Date(2026, time.November, 26, 9, 30, 0, 0, time.UTC)),
		Actor:         &auditv1.Event_Actor{Kind: auditv1.Event_Actor_KIND_OPERATOR, Subject: "alice"},
		Action:        auditv1.Event_ACTION_RULESET_ACTIVATED,
		Target:        &auditv1.Event_Target{Resource: controlv1.Resource_RESOURCE_RULESETS, Id: "ruleset-" + id},
		Outcome:       auditv1.Event_OUTCOME_SUCCEEDED,
		Origin:        &auditv1.Event_Origin{Component: "control-api", RequestId: "request-" + id},
		Change:        &auditv1.Event_Change{After: "content-" + id},
	}
}

func publishAudit(t *testing.T, addresses []string, topic string, records ...*kgo.Record) {
	t.Helper()
	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...), kgo.DefaultProduceTopic(topic))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.ProduceSync(ctx, records...).FirstErr(); err != nil {
		t.Fatalf("publish the audit events: %v", err)
	}
}

func keyed(t *testing.T, key string, recorded *auditv1.Event) *kgo.Record {
	t.Helper()
	encoded, err := proto.Marshal(recorded)
	if err != nil {
		t.Fatalf("encode an audit event: %v", err)
	}
	return &kgo.Record{Key: []byte(key), Value: encoded}
}

// Runs the writer as cmd/audit-writer composes it, in a group of its own, until
// the group has committed past every record the topic holds.
func chainAudit(t *testing.T, addresses []string, topic, quarantineTopic string, store *clickhouse.AuditStore, records int64) {
	t.Helper()
	group := fmt.Sprintf("audit-writer-%d", time.Now().UnixNano())
	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      addresses,
		Topic:        topic,
		Group:        group,
		ClientID:     "integration-test",
		MaxRecords:   3,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(metrics.New("integration")),
	})
	if err != nil {
		t.Fatalf("build the consumer: %v", err)
	}
	defer consumer.Close()

	refused, err := broker.NewQuarantine(broker.Config{Brokers: addresses, Topic: quarantineTopic, MaxMessageBytes: temporaryCarriage, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the quarantine publisher: %v", err)
	}
	defer refused.Close()

	component, err := auditstore.NewWriter(auditstore.WriterOptions{
		Source:        auditFetchedBy(consumer),
		Store:         store,
		Quarantine:    auditQuarantine(refused),
		Metrics:       auditstore.NewMetrics(metrics.New("integration")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  30 * time.Second,
		RetryDelay:    100 * time.Millisecond,
		MaxRetryDelay: time.Second,
	})
	if err != nil {
		t.Fatalf("build the writer: %v", err)
	}

	writing, stopWriting := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- component.Run(writing) }()
	awaitCommitted(t, addresses, topic, group, records)
	stopWriting()
	if err := <-stopped; err != nil && !isCancellation(err) {
		t.Fatalf("the writer stopped with %v", err)
	}
}

// What a verifier reads: every row of a chain in the order of its sequence, a
// row written twice by a retry or by two writers being one entry.
func storedChain(t *testing.T, connection driver.Conn, chain string) []*auditv1.Entry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := connection.Query(ctx,
		"SELECT sequence, previous, digest, event FROM audit_entries WHERE chain = ? ORDER BY sequence", chain)
	if err != nil {
		t.Fatalf("read chain %q: %v", chain, err)
	}
	defer func() { _ = rows.Close() }()
	var entries []*auditv1.Entry
	for rows.Next() {
		var (
			sequence                uint64
			previous, digest, event string
		)
		if err := rows.Scan(&sequence, &previous, &digest, &event); err != nil {
			t.Fatalf("read chain %q: %v", chain, err)
		}
		entry := &auditv1.Entry{Event: []byte(event), Chain: chain, Sequence: sequence, Previous: []byte(previous), Digest: []byte(digest)}
		if last := len(entries) - 1; last >= 0 && entries[last].GetSequence() == sequence {
			if !proto.Equal(entries[last], entry) {
				t.Fatalf("chain %q holds two different entries at sequence %d", chain, sequence)
			}
			continue
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read chain %q: %v", chain, err)
	}
	return entries
}

func chainedIDs(t *testing.T, connection driver.Conn, chain string, length uint64) []string {
	t.Helper()
	entries := storedChain(t, connection, chain)
	end, err := audit.Chain{Name: chain}.Verify(entries)
	if err != nil {
		t.Fatalf("chain %q as stored does not verify: %v", chain, err)
	}
	if end.Sequence != length {
		t.Fatalf("chain %q reaches %d, want %d", chain, end.Sequence, length)
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		var decoded auditv1.Event
		if err := proto.Unmarshal(entry.GetEvent(), &decoded); err != nil {
			t.Fatalf("an entry of chain %q holds no event: %v", chain, err)
		}
		ids = append(ids, decoded.GetEventId())
	}
	return ids
}

func auditRows(t *testing.T, connection driver.Conn) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var rows uint64
	if err := connection.QueryRow(ctx, "SELECT count() FROM audit_entries").Scan(&rows); err != nil {
		t.Fatalf("count the audit entries: %v", err)
	}
	return rows
}

func TestTheAuditWriterChainsEachTenantInTheOrderTheTopicHoldsIt(t *testing.T) {
	addresses := brokers(t)
	store, connection := ownAuditStore(t, storeAddress(t))
	first, second := tenant(t), tenant(t)+"-b"

	topic := temporaryTopic(t, addresses)
	quarantineTopic := temporaryTopic(t, addresses)
	invalid := auditEvent("a4", first)
	invalid.Actor = nil
	publishAudit(t, addresses, topic,
		keyed(t, first, auditEvent("a1", first)),
		keyed(t, second, auditEvent("b1", second)),
		keyed(t, "", auditEvent("01", "")),
		keyed(t, first, auditEvent("a2", first)),
		keyed(t, first, auditEvent("a1", first)),
		keyed(t, first, invalid),
		keyed(t, second, auditEvent("a5", first)),
		keyed(t, "", auditEvent("02", "")),
		keyed(t, first, auditEvent("a3", first)),
	)
	chainAudit(t, addresses, topic, quarantineTopic, store, 9)

	if ids := chainedIDs(t, connection, first, 3); !slices.Equal(ids, []string{"a1", "a2", "a3"}) {
		t.Errorf("the first tenant's chain holds %v", ids)
	}
	if ids := chainedIDs(t, connection, second, 1); !slices.Equal(ids, []string{"b1"}) {
		t.Errorf("the second tenant's chain holds %v", ids)
	}
	if ids := chainedIDs(t, connection, "", 2); !slices.Equal(ids, []string{"01", "02"}) {
		t.Errorf("the platform's chain holds %v", ids)
	}
	reasons := quarantinedReasons(t, addresses, quarantineTopic, 2)
	slices.Sort(reasons)
	if want := []string{auditstore.ReasonContractViolation, auditstore.ReasonMisplaced}; !slices.Equal(reasons, want) {
		t.Errorf("the quarantine holds %v, want %v", reasons, want)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var (
		action, subject, target string
		occurred                time.Time
		position                int64
	)
	if err := connection.QueryRow(ctx,
		"SELECT action, actor_subject, target_id, occurred_at, log_offset FROM audit_entries WHERE chain = ? AND sequence = 2", first,
	).Scan(&action, &subject, &target, &occurred, &position); err != nil {
		t.Fatalf("read an entry's columns: %v", err)
	}
	if action != "ruleset_activated" || subject != "alice" || target != "ruleset-a2" || !occurred.Equal(auditEvent("a2", first).GetOccurredAt().AsTime()) || position < 0 {
		t.Errorf("the entry is filed under %q by %q on %q at %s, offset %d", action, subject, target, occurred, position)
	}
}

// The chain is a function of the topic: a writer reading it again from the start,
// as a new group or a writer whose position was lost does, finds every record
// chained and writes nothing.
func TestReadingTheAuditTopicAgainMakesTheSameChain(t *testing.T) {
	addresses := brokers(t)
	store, connection := ownAuditStore(t, storeAddress(t))
	owner := tenant(t)

	topic := temporaryTopic(t, addresses)
	quarantineTopic := temporaryTopic(t, addresses)
	var records []*kgo.Record
	for index := range 7 {
		records = append(records, keyed(t, owner, auditEvent(fmt.Sprintf("%02x", index), owner)))
	}
	publishAudit(t, addresses, topic, records...)

	chainAudit(t, addresses, topic, quarantineTopic, store, 7)
	before := storedChain(t, connection, owner)
	held := auditRows(t, connection)

	chainAudit(t, addresses, topic, quarantineTopic, store, 7)
	after := storedChain(t, connection, owner)
	if !slices.EqualFunc(before, after, func(a, b *auditv1.Entry) bool { return proto.Equal(a, b) }) {
		t.Error("reading the topic again changed the chain")
	}
	if rows := auditRows(t, connection); rows != held {
		t.Errorf("reading the topic again wrote %d rows over the %d the store held", rows-held, held)
	}
	chainedIDs(t, connection, owner, 7)
}

func TestTheAuditStoreAnswersWhereEachChainStandsAndWhatItHolds(t *testing.T) {
	store, connection := ownAuditStore(t, storeAddress(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var rows []auditstore.Row
	chains := map[string]audit.Chain{"tenant-a": {Name: "tenant-a"}, "": {Name: ""}}
	for index, name := range []string{"tenant-a", "", "tenant-a", "tenant-a"} {
		recorded := auditEvent(fmt.Sprintf("%02x", index), name)
		encoded, err := proto.Marshal(recorded)
		if err != nil {
			t.Fatal(err)
		}
		entry, next, err := chains[name].Append(encoded)
		if err != nil {
			t.Fatal(err)
		}
		chains[name] = next
		rows = append(rows, auditstore.Row{
			Chain: entry.GetChain(), Sequence: entry.GetSequence(), Previous: entry.GetPrevious(), Digest: entry.GetDigest(),
			EventID: recorded.GetEventId(), OccurredAt: recorded.GetOccurredAt().AsTime(), Action: audit.ActionName(recorded.GetAction()),
			ActorSubject: recorded.GetActor().GetSubject(), TargetID: recorded.GetTarget().GetId(),
			LogPartition: 1, LogOffset: int64(10 + index), Event: entry.GetEvent(),
		})
	}
	for range 2 {
		if err := store.Append(ctx, rows); err != nil {
			t.Fatalf("append the entries: %v", err)
		}
	}
	if held := auditRows(t, connection); held != uint64(len(rows)) {
		t.Errorf("an insert retried with the same entries left %d rows, want %d", held, len(rows))
	}

	heads, err := store.Heads(ctx, []string{"tenant-a", "", "tenant-unknown"})
	if err != nil {
		t.Fatalf("read the heads: %v", err)
	}
	if head := heads["tenant-a"]; head.Sequence != 3 || !bytes.Equal(head.Digest, chains["tenant-a"].Head) || head.Partition != 1 || head.Offset != 13 {
		t.Errorf("tenant-a stands at %+v", head)
	}
	if head := heads[""]; head.Sequence != 1 || !bytes.Equal(head.Digest, chains[""].Head) || head.Offset != 11 {
		t.Errorf("the platform's chain stands at %+v", head)
	}
	if _, found := heads["tenant-unknown"]; found || len(heads) != 2 {
		t.Errorf("the heads are %v", heads)
	}

	held, err := store.Chained(ctx, map[string][]string{"tenant-a": {"00", "01", "03", "ff"}, "": {"01", "02"}})
	if err != nil {
		t.Fatalf("read which events the chains hold: %v", err)
	}
	if want := map[string]uint64{"00": 1, "03": 3}; !equalHeld(held["tenant-a"], want) {
		t.Errorf("tenant-a holds %v, want %v: an event of another chain is not one this chain holds", held["tenant-a"], want)
	}
	if want := map[string]uint64{"01": 1}; !equalHeld(held[""], want) {
		t.Errorf("the platform's chain holds %v, want %v: an event of another chain is not one this chain holds", held[""], want)
	}

	wide := []string{"tenant-a", ""}
	identifiers := []string{"00", "03"}
	for index := range 300 {
		wide = append(wide, fmt.Sprintf("tenant-absent-%03d", index))
		identifiers = append(identifiers, fmt.Sprintf("%064x", 1_000+index))
	}
	if heads, err := store.Heads(ctx, wide); err != nil || len(heads) != 2 || heads["tenant-a"].Sequence != 3 || heads[""].Sequence != 1 {
		t.Errorf("asked about %d chains at once, the store answered %v (%v)", len(wide), heads, err)
	}
	if held, err := store.Chained(ctx, map[string][]string{"tenant-a": identifiers}); err != nil || !equalHeld(held["tenant-a"], map[string]uint64{"00": 1, "03": 3}) {
		t.Errorf("asked about %d events at once, the store answered %v (%v)", len(identifiers), held, err)
	}

	conflicting := rows[3]
	conflicting.Digest = bytes.Repeat([]byte{0x00}, 32)
	conflicting.LogOffset = 99
	if err := store.Append(ctx, []auditstore.Row{conflicting}); err != nil {
		t.Fatalf("append a conflicting entry: %v", err)
	}
	for range 3 {
		heads, err := store.Heads(ctx, []string{"tenant-a"})
		if err != nil {
			t.Fatalf("read the heads: %v", err)
		}
		if head := heads["tenant-a"]; head.Offset != 99 {
			t.Fatalf("two entries at the newest sequence were resolved to the one at offset %d, not the smaller digest", head.Offset)
		}
	}
}

func equalHeld(got, want map[string]uint64) bool {
	if len(got) != len(want) {
		return false
	}
	for id, sequence := range want {
		if got[id] != sequence {
			return false
		}
	}
	return true
}

type auditSource struct{ consumer *broker.Consumer }

func auditFetchedBy(consumer *broker.Consumer) auditstore.Source {
	return auditSource{consumer: consumer}
}

func (s auditSource) Consume(ctx context.Context, deliver auditstore.Deliver) error {
	return s.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		converted := make([]auditstore.Record, 0, len(records))
		for _, record := range records {
			converted = append(converted, auditstore.Record{Partition: record.Partition, Offset: record.Offset, Key: record.Key, Value: record.Value})
		}
		return deliver(ctx, converted)
	})
}

type auditQuarantinedTo func(ctx context.Context, refused []auditstore.Refused) error

func (q auditQuarantinedTo) Publish(ctx context.Context, refused []auditstore.Refused) error {
	return q(ctx, refused)
}

func auditQuarantine(topic *broker.Quarantine) auditQuarantinedTo {
	return func(ctx context.Context, refused []auditstore.Refused) error {
		converted := make([]broker.Refused, 0, len(refused))
		for _, entry := range refused {
			converted = append(converted, broker.Refused{Key: entry.Key, Value: entry.Value, Reason: entry.Reason, Detail: entry.Detail, Partition: entry.Partition, Offset: entry.Offset})
		}
		return topic.Publish(ctx, converted)
	}
}
