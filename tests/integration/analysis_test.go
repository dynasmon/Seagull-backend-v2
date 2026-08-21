//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
)

// The runtime boundary of the second consumer: it joins a group of its own on
// the topic the gateway publishes to, works through what is there, and advances
// its committed position past a record it cannot read.
func TestTheEngineConsumesTheBackboneInAGroupOfItsOwn(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	group := fmt.Sprintf("analysis-engine-%d", time.Now().UnixNano())

	admitEvents(t, addresses, topic, 4)
	publishRaw(t, addresses, topic, []byte("this is not a seagull.event.v1.Event"))

	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      addresses,
		Topic:        topic,
		Group:        group,
		ClientID:     "integration-test",
		MaxRecords:   500,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(metrics.New("integration")),
	})
	if err != nil {
		t.Fatalf("build the consumer: %v", err)
	}
	t.Cleanup(consumer.Close)

	verifyCtx, cancelVerify := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelVerify()
	if _, err := consumer.VerifyTopics(verifyCtx, broker.Topic{
		Name:        topic,
		Partitions:  3,
		Replicas:    1,
		Retention:   time.Hour,
		Cleanup:     "delete",
		Compression: "zstd",
	}); err != nil {
		t.Fatalf("the engine refused a topic it should accept: %v", err)
	}

	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:  analysedBy(consumer),
		Metrics: analysis.NewMetrics(metrics.New("integration")),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("build the engine: %v", err)
	}

	running, stop := context.WithCancel(context.Background())
	defer stop()

	stopped := make(chan error, 1)
	go func() { stopped <- engine.Run(running) }()

	awaitCommitted(t, addresses, topic, group, 5)

	stop()
	if err := <-stopped; err != nil && !isCancellation(err) {
		t.Fatalf("the engine stopped with %v", err)
	}
}

func admitEvents(t *testing.T, addresses []string, topic string, count int) {
	t.Helper()

	publisher, err := broker.NewPublisher(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	admitter, err := ingest.NewAdmitter(publisher, ingest.Policy{
		Gateway:           "gateway-integration",
		TenantID:          tenant(t),
		MaxEventsPerBatch: 100,
		Event:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
	}, ingest.NewMetrics(metrics.New("integration")))
	if err != nil {
		t.Fatalf("build the admitter: %v", err)
	}

	at := time.Now().UTC()
	batch := fixtures.Batch("batch-analysis")
	for index := range count {
		batch.Events = append(batch.Events, fixtures.SSHAuthentication{
			EventID:  fmt.Sprintf("analysis-%09d", index),
			At:       at,
			Sequence: uint64(index),
		}.Event())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := admitter.Admit(ctx, agentidentity.Identity{AgentID: "web-01"}, batch); err != nil {
		t.Fatalf("admit the batch: %v", err)
	}
}

func publishRaw(t *testing.T, addresses []string, topic string, payload []byte) {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...), kgo.RequiredAcks(kgo.AllISRAcks()))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.ProduceSync(ctx, &kgo.Record{Topic: topic, Key: []byte("web-01"), Value: payload}).FirstErr(); err != nil {
		t.Fatalf("publish a raw record: %v", err)
	}
}

// The engine has no store to look in, so what it did is read from the group
// position it committed — which is the property the runtime has to hold.
func awaitCommitted(t *testing.T, addresses []string, topic, group string, expected int64) {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	defer client.Close()

	admin := kadm.NewClient(client)
	deadline := time.Now().Add(90 * time.Second)

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		offsets, err := admin.FetchOffsets(ctx, group)
		cancel()

		var committed int64
		if err == nil {
			offsets.Each(func(offset kadm.OffsetResponse) {
				if offset.Topic == topic && offset.Err == nil && offset.At > 0 {
					committed += offset.At
				}
			})
		}
		if committed >= expected {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the engine committed %d of %d records before the deadline", committed, expected)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func analysedBy(consumer *broker.Consumer) analysis.Source {
	return analysisSource{consumer: consumer}
}

type analysisSource struct{ consumer *broker.Consumer }

func (a analysisSource) Consume(ctx context.Context, deliver analysis.Deliver) error {
	return a.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		converted := make([]analysis.Record, 0, len(records))
		for _, record := range records {
			converted = append(converted, analysis.Record{
				Partition: record.Partition,
				Offset:    record.Offset,
				Key:       record.Key,
				Value:     record.Value,
			})
		}
		return deliver(ctx, converted)
	})
}
