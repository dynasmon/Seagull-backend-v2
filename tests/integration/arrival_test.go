//go:build integration

package integration_test

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

type arrival struct {
	partition int32
	offset    int64
	batch     string
}

func arrivedAt(owner, eventID, batchID string, partition int32, offset int64) eventstore.Row {
	at := time.Date(2026, time.August, 17, 14, 0, 0, 0, time.UTC)
	record := fixtures.SSHAuthentication{EventID: eventID, AgentID: "web-01", At: at}.Event()
	record.Origin.TenantId = owner
	record.Reception = &eventv1.Reception{IngestTime: timestamppb.New(at), Gateway: "ingest-gateway", BatchId: batchID}
	row := eventstore.Project(record)
	row.LogPartition, row.LogOffset = partition, offset
	return row
}

func arrivals(t *testing.T, address, owner string) map[string]arrival {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rows, err := inspector(t, address).Query(ctx,
		"SELECT event_id, log_partition, log_offset, batch_id FROM security_events FINAL WHERE tenant_id = ?", owner)
	if err != nil {
		t.Fatalf("read where the stored events arrived: %v", err)
	}
	defer func() { _ = rows.Close() }()

	held := map[string]arrival{}
	for rows.Next() {
		var (
			eventID string
			kept    arrival
		)
		if err := rows.Scan(&eventID, &kept.partition, &kept.offset, &kept.batch); err != nil {
			t.Fatalf("read where a stored event arrived: %v", err)
		}
		held[eventID] = kept
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read where the stored events arrived: %v", err)
	}
	return held
}

func TestAnEventDeliveredTwiceKeepsItsFirstArrival(t *testing.T) {
	address := storeAddress(t)
	store := migratedStore(t, address)
	owner := tenant(t)

	apart := "aaaaaaaa-7777-4777-8777-000000000001"
	together := "aaaaaaaa-7777-4777-8777-000000000002"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, written := range [][]eventstore.Row{
		{arrivedAt(owner, apart, "batch-sent", 1, 5)},
		{arrivedAt(owner, apart, "batch-sent-again", 1, 12)},
		{arrivedAt(owner, together, "batch-sent", 1, 7), arrivedAt(owner, together, "batch-sent-again", 1, 31)},
	} {
		if err := store.Store(ctx, written); err != nil {
			t.Fatalf("write %d arrivals: %v", len(written), err)
		}
	}

	want := map[string]arrival{
		apart:    {partition: 1, offset: 5, batch: "batch-sent"},
		together: {partition: 1, offset: 7, batch: "batch-sent"},
	}
	if got := arrivals(t, address, owner); !maps.Equal(got, want) {
		t.Fatalf("the store kept %+v of events delivered twice, want their first arrivals %+v", got, want)
	}
}

func TestARowWithoutAPositionIsNotOneAtOffsetZero(t *testing.T) {
	address := storeAddress(t)
	store := migratedStore(t, address)
	owner := tenant(t)

	unplaced := "aaaaaaaa-7777-4777-8777-000000000003"
	first := "aaaaaaaa-7777-4777-8777-000000000004"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := insertAsReleased(ctx, inspector(t, address), arrivedAt(owner, unplaced, "batch-sent", 0, 0)); err != nil {
		t.Fatalf("write as the release before positions: %v", err)
	}
	for _, written := range []eventstore.Row{
		arrivedAt(owner, first, "batch-first", 0, 0),
		arrivedAt(owner, unplaced, "batch-sent-again", 0, 3),
	} {
		if err := store.Store(ctx, []eventstore.Row{written}); err != nil {
			t.Fatalf("write %s: %v", written.EventID, err)
		}
	}

	want := map[string]arrival{
		unplaced: {partition: -1, offset: -1},
		first:    {partition: 0, offset: 0, batch: "batch-first"},
	}
	if got := arrivals(t, address, owner); !maps.Equal(got, want) {
		t.Fatalf("the store holds %+v, want the event stored before positions unplaced and the first record at offset zero: %+v",
			got, want)
	}
}

// Six agents send three rounds of four events each, every round older than the
// one before, so the order the store sorts by is not the order they arrived in;
// one batch is sent twice, as an agent does when its acknowledgement is lost.
func TestAPartitionReadBackInPositionOrderIsWhatTheTopicHeld(t *testing.T) {
	addresses := brokers(t)
	address := storeAddress(t)
	store := migratedStore(t, address)
	owner := tenant(t)
	topic := temporaryTopic(t, addresses)

	publisher, err := broker.NewPublisher(broker.Config{
		Brokers:         addresses,
		Topic:           topic,
		MaxMessageBytes: temporaryCarriage,
		ClientID:        "integration-test",
	})
	if err != nil {
		t.Fatalf("build the publisher: %v", err)
	}
	t.Cleanup(publisher.Close)
	admitter, err := ingest.NewAdmitter(publisher, ingest.Policy{
		Gateway:           "gateway-integration",
		MaxEventsPerBatch: 100,
		Event:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
	}, ingest.NewMetrics(metrics.New("integration")))
	if err != nil {
		t.Fatalf("build the admitter: %v", err)
	}
	admit := func(agentID string, batch *ingestv1.EventBatch) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if acknowledged, err := admitter.Admit(ctx, agentidentity.Identity{AgentID: agentID}, owner, batch); err != nil || !acknowledged.GetDurable() {
			t.Fatalf("admit %s of %s: %v", batch.GetBatchId(), agentID, err)
		}
	}

	newest := time.Now().UTC().Truncate(time.Millisecond)
	agents := []string{"web-01", "web-02", "web-03", "web-04", "web-05", "web-06"}
	var lost *ingestv1.EventBatch
	for round := range 3 {
		for index, agentID := range agents {
			events := make([]*eventv1.Event, 0, 4)
			for sent := range 4 {
				events = append(events, fixtures.SSHAuthentication{
					EventID: fmt.Sprintf("%08d-0000-4000-8000-%012d", round*10+index, sent),
					At:      newest.Add(-time.Duration(round*4+sent) * time.Second),
				}.Event())
			}
			batch := fixtures.Batch(fmt.Sprintf("batch-%d-%d", round, index), events...)
			admit(agentID, batch)
			if round == 0 && agentID == "web-02" {
				lost = batch
			}
		}
	}
	admit("web-02", lost)

	written := writeTopic(t, addresses, topic, store)
	waitFor(t, address, owner, uint64(len(agents)*3*4))
	written()

	held := consume(t, addresses, topic, len(agents)*3*4+4)
	slices.SortFunc(held, func(a, b *kgo.Record) int {
		if a.Partition != b.Partition {
			return cmp.Compare(a.Partition, b.Partition)
		}
		return cmp.Compare(a.Offset, b.Offset)
	})
	var want []string
	seen := map[string]bool{}
	for _, record := range held {
		var decoded eventv1.Event
		if err := proto.Unmarshal(record.Value, &decoded); err != nil {
			t.Fatalf("read partition %d offset %d: %v", record.Partition, record.Offset, err)
		}
		name := decoded.GetOrigin().GetAgentId() + "/" + decoded.GetEventId()
		if !seen[name] {
			seen[name] = true
			want = append(want, fmt.Sprintf("%d:%d %s", record.Partition, record.Offset, name))
		}
	}

	inPositionOrder := storedIn(t, address, owner, "log_partition, log_offset")
	if !slices.Equal(inPositionOrder, want) {
		t.Fatalf("read in position order the store holds\n%v\nand the topic held\n%v", inPositionOrder, want)
	}
	if slices.Equal(storedIn(t, address, owner, "event_time, agent_id, event_id"), want) {
		t.Fatal("the store's own order is the topic's, so this proves nothing about positions")
	}
}

func writeTopic(t *testing.T, addresses []string, topic string, store *clickhouse.Store) func() {
	t.Helper()

	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      addresses,
		Topic:        topic,
		Group:        fmt.Sprintf("event-writer-%d", time.Now().UnixNano()),
		ClientID:     "integration-test",
		MaxRecords:   7,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(metrics.New("integration")),
	})
	if err != nil {
		t.Fatalf("build the consumer: %v", err)
	}
	t.Cleanup(consumer.Close)
	refused, err := broker.NewQuarantine(broker.Config{
		Brokers:         addresses,
		Topic:           temporaryTopic(t, addresses),
		MaxMessageBytes: temporaryCarriage,
		ClientID:        "integration-test",
	})
	if err != nil {
		t.Fatalf("build the quarantine publisher: %v", err)
	}
	t.Cleanup(refused.Close)
	writer, err := eventstore.NewWriter(eventstore.WriterOptions{
		Source:        fetchedBy(consumer),
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

	writing, stop := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- writer.Run(writing) }()
	return func() {
		stop()
		if err := <-stopped; err != nil && !isCancellation(err) {
			t.Fatalf("the writer stopped with %v", err)
		}
	}
}

func storedIn(t *testing.T, address, owner, order string) []string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rows, err := inspector(t, address).Query(ctx,
		"SELECT log_partition, log_offset, agent_id, event_id FROM security_events FINAL WHERE tenant_id = ? ORDER BY "+order, owner)
	if err != nil {
		t.Fatalf("read the stored events by %s: %v", order, err)
	}
	defer func() { _ = rows.Close() }()

	var stored []string
	for rows.Next() {
		var (
			partition        int32
			offset           int64
			agentID, eventID string
		)
		if err := rows.Scan(&partition, &offset, &agentID, &eventID); err != nil {
			t.Fatalf("read a stored event: %v", err)
		}
		stored = append(stored, fmt.Sprintf("%d:%d %s/%s", partition, offset, agentID, eventID))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read the stored events by %s: %v", order, err)
	}
	return stored
}
