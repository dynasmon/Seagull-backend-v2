//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// One analysis engine, run for as long as the caller keeps it. Each replica
// builds its own keeper, because state held in a process is what a crash and a
// revocation both take away.
type replica struct {
	consumer *broker.Consumer
	engine   *analysis.Engine
	stop     context.CancelFunc
	stopped  chan error
	done     bool
}

// What temporaryTopic creates, which is what a reader claiming the whole stream
// is held to here.
const partitionsPerTopic = 3

type replicaOptions struct {
	addresses []string
	topic     string
	found     string
	group     string
	program   *detection.Program
	recover   time.Duration
	sole      bool
}

func start(t *testing.T, options replicaOptions) *replica {
	t.Helper()

	recovery := broker.Recovery(nil)
	if options.recover > 0 || options.sole {
		recovery = func(held int32) (time.Duration, error) {
			if options.sole && held < partitionsPerTopic {
				return 0, fmt.Errorf("a rule needs the whole stream and this reader holds %d of %d partitions",
					held, partitionsPerTopic)
			}
			return options.recover, nil
		}
	}

	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      options.addresses,
		Topic:        options.topic,
		Group:        options.group,
		ClientID:     "integration-test",
		MaxRecords:   500,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(metrics.New("integration")),
		Recovery:     recovery,
	})
	if err != nil {
		t.Fatalf("build the consumer: %v", err)
	}

	detections, err := broker.NewDetections(broker.Config{
		Brokers:  options.addresses,
		Topic:    options.found,
		ClientID: "integration-test",
	})
	if err != nil {
		consumer.Close()
		t.Fatalf("build the detection publisher: %v", err)
	}

	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:         analysedBy(consumer),
		Rules:          pinnedTo(t, options.program),
		State:          remembering(t),
		Detections:     detections,
		Metrics:        analysis.NewMetrics(metrics.New("integration")),
		Logger:         slog.New(slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})),
		PublishTimeout: 30 * time.Second,
		RetryDelay:     100 * time.Millisecond,
		MaxRetryDelay:  time.Second,
	})
	if err != nil {
		consumer.Close()
		detections.Close()
		t.Fatalf("build the engine: %v", err)
	}

	running, stop := context.WithCancel(context.Background())
	held := &replica{consumer: consumer, engine: engine, stop: stop, stopped: make(chan error, 1)}
	go func() {
		held.stopped <- engine.Run(running)
		consumer.Close()
		detections.Close()
	}()
	t.Cleanup(func() { held.terminate(t) })
	return held
}

func (r *replica) terminate(t *testing.T) {
	t.Helper()

	if r.done {
		return
	}
	r.done = true
	r.stop()
	select {
	case err := <-r.stopped:
		if err != nil && !isCancellation(err) {
			t.Errorf("a replica stopped with %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Error("a replica did not stop")
	}
}

func (r *replica) failed(t *testing.T) error {
	t.Helper()

	r.done = true
	select {
	case err := <-r.stopped:
		return err
	case <-time.After(60 * time.Second):
		return nil
	}
}

// Events from one agent, timed now, so every one of them lands on the partition
// that agent's key chooses and inside any window a rule declares.
func admitFrom(t *testing.T, addresses []string, topic, owner, agent string, from, count int) {
	t.Helper()

	publisher, err := broker.NewPublisher(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the publisher: %v", err)
	}
	defer publisher.Close()

	admitter, err := ingest.NewAdmitter(publisher, ingest.Policy{
		Gateway:           "gateway-integration",
		TenantID:          owner,
		MaxEventsPerBatch: 1000,
		Event:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
	}, ingest.NewMetrics(metrics.New("integration")))
	if err != nil {
		t.Fatalf("build the admitter: %v", err)
	}

	at := time.Now().UTC()
	batch := fixtures.Batch(fmt.Sprintf("batch-%s-%d", agent, from))
	for index := from; index < from+count; index++ {
		batch.Events = append(batch.Events, fixtures.SSHAuthentication{
			EventID:  fmt.Sprintf("%s-%09d", agent, index),
			At:       at,
			Sequence: uint64(index),
		}.Event())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := admitter.Admit(ctx, agentidentity.Identity{AgentID: agent}, batch); err != nil {
		t.Fatalf("admit a batch from %s: %v", agent, err)
	}
}

func detected(t *testing.T, addresses []string, topic string, wanted int, within time.Duration) int {
	t.Helper()

	client, err := kgo.NewClient(
		kgo.SeedBrokers(addresses...),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		t.Fatalf("build a consumer: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()

	found := 0
	for found < wanted && ctx.Err() == nil {
		fetches := client.PollRecords(ctx, 100)
		fetches.EachRecord(func(*kgo.Record) { found++ })
	}
	return found
}

// A rule that reaches its threshold only if the window survived the restart:
// fifteen events before, five after, and a threshold of twenty.
func acrossARestart(t *testing.T) *detection.Program {
	t.Helper()

	program, err := detection.Compile(detection.Rule{
		ID:          "authentication.repeated_failures",
		Revision:    1,
		Name:        "Repeated authentication failures from one address",
		Description: "More failures from one address against one agent than an estate should see.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue("failure")},
		},
		Count: detection.Count{
			AtLeast: 20,
			Within:  10 * time.Minute,
			GroupBy: []detection.Field{"authentication.network.source.ip", "origin.agent_id"},
		},
		Severity: detection.High,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("compile the rule: %v", err)
	}
	return program
}

// The whole wave in one test. Fifteen events are decided and their positions
// committed; the process is killed; five more arrive. A reader that resumed at
// the committed position would see five events and say nothing, and the twenty
// inside the window would go unreported.
func TestARestartInsideAWindowStillReachesTheThreshold(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	found := temporaryTopic(t, addresses)
	group := fmt.Sprintf("analysis-engine-%d", time.Now().UnixNano())
	owner := tenant(t)
	program := acrossARestart(t)

	admitFrom(t, addresses, topic, owner, "web-01", 0, 15)

	first := start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: program, recover: 15 * time.Minute,
	})
	awaitCommitted(t, addresses, topic, group, 15)
	first.terminate(t)

	admitFrom(t, addresses, topic, owner, "web-01", 15, 5)

	start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: program, recover: 15 * time.Minute,
	})

	if made := detected(t, addresses, found, 1, 60*time.Second); made == 0 {
		t.Fatal("twenty events inside the window produced no detection after the restart")
	}
}

// The control for the test above. Without the read back, the same stream and
// the same rule produce nothing, which is what makes the assertion mean
// something rather than pass for another reason.
func TestARestartThatDoesNotReadItsWindowBackFindsNothing(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	found := temporaryTopic(t, addresses)
	group := fmt.Sprintf("analysis-engine-%d", time.Now().UnixNano())
	owner := tenant(t)
	program := acrossARestart(t)

	admitFrom(t, addresses, topic, owner, "web-01", 0, 15)

	first := start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group, program: program,
	})
	awaitCommitted(t, addresses, topic, group, 15)
	first.terminate(t)

	admitFrom(t, addresses, topic, owner, "web-01", 15, 5)

	start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group, program: program,
	})

	if made := detected(t, addresses, found, 1, 20*time.Second); made != 0 {
		t.Fatalf("a reader that never read its window back made %d detections", made)
	}
}

// A partition moving between processes is a restart of the state that partition
// feeds. The second replica takes some of the stream and has to arrive at the
// same answer the first would have.
func TestAPartitionMovingToAnotherReplicaKeepsTheCountItWasCarrying(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	found := temporaryTopic(t, addresses)
	group := fmt.Sprintf("analysis-engine-%d", time.Now().UnixNano())
	owner := tenant(t)
	program := acrossARestart(t)

	agents := []string{"web-01", "web-02", "web-03"}
	for _, agent := range agents {
		admitFrom(t, addresses, topic, owner, agent, 0, 15)
	}

	first := start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: program, recover: 15 * time.Minute,
	})
	awaitCommitted(t, addresses, topic, group, 45)

	start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: program, recover: 15 * time.Minute,
	})
	awaitAssignment(t, first, 3)

	for _, agent := range agents {
		admitFrom(t, addresses, topic, owner, agent, 15, 5)
	}

	if made := detected(t, addresses, found, len(agents), 90*time.Second); made < len(agents) {
		t.Fatalf("%d of %d agents reached their threshold after the partitions were shared out",
			made, len(agents))
	}
}

// The mirror of the test above: a replica goes away and its partitions land on
// one that never saw the events they carried.
func TestAReplicaGoingAwayLeavesItsCountsWithWhoeverTakesThePartitions(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	found := temporaryTopic(t, addresses)
	group := fmt.Sprintf("analysis-engine-%d", time.Now().UnixNano())
	owner := tenant(t)
	program := acrossARestart(t)

	agents := []string{"web-01", "web-02", "web-03"}
	for _, agent := range agents {
		admitFrom(t, addresses, topic, owner, agent, 0, 15)
	}

	first := start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: program, recover: 15 * time.Minute,
	})
	second := start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: program, recover: 15 * time.Minute,
	})
	awaitCommitted(t, addresses, topic, group, 45)
	awaitAssignment(t, first, partitionsPerTopic)

	second.terminate(t)

	for _, agent := range agents {
		admitFrom(t, addresses, topic, owner, agent, 15, 5)
	}

	if made := detected(t, addresses, found, len(agents), 120*time.Second); made < len(agents) {
		t.Fatalf("%d of %d agents reached their threshold after a replica went away",
			made, len(agents))
	}
}

// A claim to hold the whole stream, broken by a second reader. The engine stops
// rather than counting a third of what the rule was written to find.
func TestAReaderThatLosesTheWholeStreamStopsRatherThanCountPartOfIt(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	found := temporaryTopic(t, addresses)
	group := fmt.Sprintf("analysis-engine-%d", time.Now().UnixNano())
	owner := tenant(t)
	program := acrossARestart(t)

	admitFrom(t, addresses, topic, owner, "web-01", 0, 5)

	first := start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: program, recover: time.Minute, sole: true,
	})
	awaitCommitted(t, addresses, topic, group, 5)

	second := start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: program, recover: time.Minute, sole: true,
	})

	err := second.failed(t)
	if err == nil || isCancellation(err) {
		t.Fatalf("a reader holding part of the stream went on counting across it: %v", err)
	}
	if !errorMentions(err, "holds") {
		t.Fatalf("the reader stopped for another reason: %v", err)
	}

	// The invariant is that nobody counts across a stream they hold part of, not
	// that everybody stops. A reader still holding the whole of it is the one
	// reader the rule needs and keeps going; one that was ever left with less
	// has latched a refusal and stops, whatever it holds by the time it does.
	settled(t, first)
}

func settled(t *testing.T, held *replica) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if len(held.consumer.Assigned()) == partitionsPerTopic {
			return
		}
		select {
		case err := <-held.stopped:
			held.done = true
			if err == nil || isCancellation(err) || !errorMentions(err, "holds") {
				t.Fatalf("a reader holding part of the stream stopped with %v", err)
			}
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatalf("a reader is still holding %v of %d partitions and still running",
		held.consumer.Assigned(), partitionsPerTopic)
}

func errorMentions(err error, part string) bool {
	return err != nil && strings.Contains(err.Error(), part)
}

func awaitAssignment(t *testing.T, held *replica, total int) {
	t.Helper()

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if assigned := len(held.consumer.Assigned()); assigned > 0 && assigned < total {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("the first replica still holds %v after a second one joined", held.consumer.Assigned())
}
