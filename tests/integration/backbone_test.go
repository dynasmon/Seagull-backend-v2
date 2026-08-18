//go:build integration

package integration_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func brokers(t *testing.T) []string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("SEAGULL_TEST_BROKERS"))
	if value == "" {
		t.Skip("set SEAGULL_TEST_BROKERS to run the backbone integration suite")
	}
	return strings.Split(value, ",")
}

func temporaryTopic(t *testing.T, addresses []string) string {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	t.Cleanup(client.Close)

	admin := kadm.NewClient(client)
	topic := fmt.Sprintf("security.events.raw.test.%d", time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := admin.CreateTopic(ctx, 3, 1, map[string]*string{}, topic); err != nil {
		t.Fatalf("create topic: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.DeleteTopics(cleanup, topic)
	})
	return topic
}

func TestAdmittedBatchBecomesDurableOnTheBackbone(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)

	publisher, err := broker.NewPublisher(broker.Config{
		Brokers:  addresses,
		Topic:    topic,
		ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	admitter, err := ingest.NewAdmitter(publisher, ingest.Policy{
		Gateway:           "gateway-integration",
		TenantID:          "acme",
		MaxEventsPerBatch: 100,
		Event:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
	}, ingest.NewMetrics(metrics.New("integration")))
	if err != nil {
		t.Fatalf("build admitter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	batch := fixtures.Batch("batch-integration",
		fixtures.SSHAuthentication{EventID: "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", Username: "root"}.Event(),
		fixtures.SSHAuthentication{EventID: "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb", Username: "deploy"}.Event(),
	)
	acknowledgement, err := admitter.Admit(ctx, agentidentity.Identity{AgentID: "web-01"}, batch)
	if err != nil {
		t.Fatalf("admit batch: %v", err)
	}
	if !acknowledgement.GetDurable() {
		t.Fatal("the batch was acknowledged without durability")
	}

	records := consume(t, addresses, topic, 2)
	if len(records) != 2 {
		t.Fatalf("expected 2 records on the backbone, got %d", len(records))
	}

	for _, record := range records {
		if string(record.Key) != "web-01" {
			t.Fatalf("records must be keyed by agent for per-agent ordering, got %q", record.Key)
		}
		if header(record, "schema") != "seagull.event.v1.Event" {
			t.Fatalf("record does not describe its schema: %+v", record.Headers)
		}

		var decoded eventv1.Event
		if err := proto.Unmarshal(record.Value, &decoded); err != nil {
			t.Fatalf("decode record: %v", err)
		}
		if decoded.GetOrigin().GetAgentId() != "web-01" || decoded.GetOrigin().GetTenantId() != "acme" {
			t.Fatalf("identity did not survive the backbone: %+v", decoded.GetOrigin())
		}
		if decoded.GetReception().GetBatchId() != "batch-integration" {
			t.Fatalf("reception did not survive the backbone: %+v", decoded.GetReception())
		}
		if decoded.GetAuthentication().GetUser().GetName() == "" {
			t.Fatal("the authentication body did not survive the backbone")
		}
	}
}

func TestPublisherReportsAnUnreachableBackbone(t *testing.T) {
	brokers(t)

	publisher, err := broker.NewPublisher(broker.Config{
		Brokers:  []string{"127.0.0.1:1"},
		Topic:    "security.events.raw",
		ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = publisher.PublishEvents(ctx, []*eventv1.Event{fixtures.SSHAuthentication{}.Event()})
	if err == nil {
		t.Fatal("publishing to an unreachable backbone reported success")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "publish") {
		t.Fatalf("unexpected failure: %v", err)
	}

	if pingErr := publisher.Ping(ctx); pingErr == nil {
		t.Fatal("an unreachable backbone reported itself healthy")
	}
}

func TestReachableBackbonePassesReadiness(t *testing.T) {
	addresses := brokers(t)

	publisher, err := broker.NewPublisher(broker.Config{
		Brokers:  addresses,
		Topic:    "security.events.raw",
		ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := publisher.Ping(ctx); err != nil {
		t.Fatalf("a reachable backbone failed readiness: %v", err)
	}
}

func TestConsumerLagIncludesRecordsWaitingForDurableProcessing(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	publisher, err := broker.NewPublisher(broker.Config{
		Brokers: addresses, Topic: topic, ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := publisher.PublishEvents(ctx, []*eventv1.Event{
		fixtures.SSHAuthentication{EventID: "10000000-0000-4000-8000-000000000001"}.Event(),
		fixtures.SSHAuthentication{EventID: "10000000-0000-4000-8000-000000000002"}.Event(),
	}); err != nil {
		t.Fatalf("publish initial records: %v", err)
	}

	registry := metrics.New("integration")
	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      addresses,
		Topic:        topic,
		Group:        fmt.Sprintf("lag-test-%d", time.Now().UnixNano()),
		ClientID:     "integration-test",
		MaxRecords:   2,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(registry),
	})
	if err != nil {
		t.Fatalf("build consumer: %v", err)
	}
	t.Cleanup(consumer.Close)

	processing := make(chan struct{}, 1)
	stopped := make(chan error, 1)
	go func() {
		stopped <- consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
			processing <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		})
	}()

	select {
	case <-processing:
	case <-ctx.Done():
		t.Fatal("the initial records were not delivered")
	}
	waitForConsumerLag(t, registry, topic, 2)
	if err := publisher.PublishEvents(ctx, []*eventv1.Event{
		fixtures.SSHAuthentication{EventID: "10000000-0000-4000-8000-000000000003"}.Event(),
		fixtures.SSHAuthentication{EventID: "10000000-0000-4000-8000-000000000004"}.Event(),
		fixtures.SSHAuthentication{EventID: "10000000-0000-4000-8000-000000000005"}.Event(),
	}); err != nil {
		t.Fatalf("publish records during processing: %v", err)
	}

	waitForConsumerLag(t, registry, topic, 5)
	cancel()
	if err := <-stopped; !errors.Is(err, context.Canceled) {
		t.Fatalf("consumer stopped with %v, want context.Canceled", err)
	}
}

func waitForConsumerLag(t *testing.T, registry *metrics.Registry, topic string, want float64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		recorder := httptest.NewRecorder()
		registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		var lag float64
		for _, line := range strings.Split(recorder.Body.String(), "\n") {
			if !strings.HasPrefix(line, "seagull_backbone_consumer_lag_records{") ||
				!strings.Contains(line, `topic="`+topic+`"`) {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 2 {
				value, err := strconv.ParseFloat(fields[1], 64)
				if err != nil {
					t.Fatalf("parse lag metric %q: %v", line, err)
				}
				lag += value
			}
		}
		if lag == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("consumer lag is %.0f, want %.0f", lag, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func consume(t *testing.T, addresses []string, topic string, expected int) []*kgo.Record {
	t.Helper()

	client, err := kgo.NewClient(
		kgo.SeedBrokers(addresses...),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		t.Fatalf("build consumer: %v", err)
	}
	t.Cleanup(client.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var collected []*kgo.Record
	for len(collected) < expected {
		fetches := client.PollRecords(ctx, expected-len(collected))
		if err := fetches.Err(); err != nil {
			t.Fatalf("consume: %v", err)
		}
		fetches.EachRecord(func(record *kgo.Record) { collected = append(collected, record) })
	}
	return collected
}

func header(record *kgo.Record, key string) string {
	for _, entry := range record.Headers {
		if entry.Key == key {
			return string(entry.Value)
		}
	}
	return ""
}
