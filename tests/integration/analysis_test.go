//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The runtime boundary of the second consumer: it joins a group of its own on
// the topic the gateway publishes to, decides every event it can route against
// the ruleset it is pinned to, and advances its committed position past both a
// record it cannot read and a class it cannot route.
func TestTheEngineConsumesTheBackboneInAGroupOfItsOwn(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	group := fmt.Sprintf("analysis-engine-%d", time.Now().UnixNano())

	admitEvents(t, addresses, topic, 4)
	publishRaw(t, addresses, topic, []byte("this is not a seagull.event.v1.Event"))
	publishRaw(t, addresses, topic, fromANewerContract(t))

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

	var reported bytes.Buffer
	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:  analysedBy(consumer),
		Rules:   pinnedTo(t, failedAuthentication(t)),
		Metrics: analysis.NewMetrics(metrics.New("integration")),
		Logger:  slog.New(slog.NewJSONHandler(&reported, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	if err != nil {
		t.Fatalf("build the engine: %v", err)
	}

	running, stop := context.WithCancel(context.Background())
	defer stop()

	stopped := make(chan error, 1)
	go func() { stopped <- engine.Run(running) }()

	awaitCommitted(t, addresses, topic, group, 6)

	stop()
	if err := <-stopped; err != nil && !isCancellation(err) {
		t.Fatalf("the engine stopped with %v", err)
	}

	// Read only after the engine has stopped, so the buffer the test reads is
	// the one the engine finished writing.
	if detections := detectionsIn(t, reported.String()); len(detections) != 4 {
		t.Fatalf("four admitted failures produced %d detections: %v", len(detections), detections)
	}
}

// A rule the admitted events answer, so what the engine decided off a real
// backbone is visible rather than inferred.
func failedAuthentication(t *testing.T) *detection.Program {
	t.Helper()

	program, err := detection.Compile(detection.Rule{
		ID:          "authentication.failed",
		Revision:    1,
		Name:        "An authentication failed",
		Description: "A rule narrow enough to be decided from one event.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue("failure")},
		},
		Severity: detection.High,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("compile the rule: %v", err)
	}
	return program
}

// The bridge an executable owns, rebuilt here because nothing may import a cmd
// package: the registry names a ruleset in its own type and the engine asks for
// a name.
func pinnedTo(t *testing.T, programs ...*detection.Program) analysis.Rules {
	t.Helper()

	snapshot, err := ruleset.Compose(programs)
	if err != nil {
		t.Fatalf("compose the ruleset: %v", err)
	}
	return heldRuleset{snapshot: snapshot}
}

type heldRuleset struct{ snapshot *ruleset.Snapshot }

func (h heldRuleset) Current() analysis.Ruleset { return h }

func (h heldRuleset) ID() string { return string(h.snapshot.ID()) }

func (h heldRuleset) For(class eventv1.EventClass) iter.Seq[*detection.Program] {
	return h.snapshot.For(class)
}

func detectionsIn(t *testing.T, reported string) []string {
	t.Helper()

	var events []string
	for _, line := range strings.Split(strings.TrimSpace(reported), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode a report: %v", err)
		}
		if entry["msg"] != "detection" {
			continue
		}
		if rule := entry["rule"]; rule != "authentication.failed" {
			t.Errorf("a detection names rule %v", rule)
		}
		events = append(events, fmt.Sprint(entry["event"]))
	}
	return events
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

// What a gateway running a newer contract admits: a well formed event carrying
// a class this build has never heard of. The engine has to advance past it
// rather than stop on it or refuse the batch.
func fromANewerContract(t *testing.T) []byte {
	t.Helper()

	record := fixtures.SSHAuthentication{EventID: "analysis-from-a-newer-contract"}.Event()
	record.EventClass = eventv1.EventClass(4242)
	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode an event from a newer contract: %v", err)
	}
	return payload
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
