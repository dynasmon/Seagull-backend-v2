//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const revocationDeadline = 30 * time.Second

// A gateway's roster as the gateway keeps it: replayed whole, then followed, and
// measured against the log by the gateway's own Currency.
type followingRoster struct {
	held     *agent.Roster
	reader   *broker.StateLog
	currency *ingest.Currency
	apply    broker.Deliver
	follow   context.CancelFunc
	followed chan error
}

func followRoster(t *testing.T, addresses []string, topic string, every, staleAfter time.Duration) *followingRoster {
	t.Helper()
	reader, err := broker.NewStateLog(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-roster"}, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)

	roster := &followingRoster{held: agent.NewRoster(), reader: reader}
	roster.apply = func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			var admission agentv1.Admission
			if err := proto.Unmarshal(record.Value, &admission); err != nil {
				return err
			}
			if err := roster.held.Apply(&admission); err != nil {
				return err
			}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := reader.Replay(ctx, roster.apply); err != nil {
		t.Fatalf("replay the agent log: %v", err)
	}

	roster.currency, err = ingest.NewCurrency(ingest.CurrencyOptions{Log: reader, Every: every, StaleAfter: staleAfter,
		Registry: metrics.New("integration-roster"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	roster.currency.Confirm(context.Background())
	running, stop := context.WithCancel(context.Background())
	go func() { _ = roster.currency.Run(running) }()
	t.Cleanup(stop)
	roster.resume(t)
	return roster
}

func (r *followingRoster) resume(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r.follow, r.followed = cancel, make(chan error, 1)
	go func() { r.followed <- r.reader.Follow(ctx, r.apply) }()
	t.Cleanup(r.pause)
}

func (r *followingRoster) pause() {
	if r.follow != nil {
		r.follow()
		<-r.followed
		r.follow = nil
	}
}

func admissionOf(agentID string, state agent.State, revision uint64) *agentv1.Admission {
	return &agentv1.Admission{AgentId: agentID, TenantId: "acme", State: state.Wire(), Revision: revision, ChangedAt: timestamppb.Now()}
}

func publishAll(t *testing.T, publisher *broker.Agents, admissions ...*agentv1.Admission) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, admission := range admissions {
		if err := publisher.Publish(ctx, admission); err != nil {
			t.Fatalf("publish the admission of %s: %v", admission.GetAgentId(), err)
		}
	}
}

func refusedWithin(rosters []*followingRoster, agentID string, deadline time.Duration) (time.Duration, bool) {
	published := time.Now()
	for time.Since(published) < deadline {
		refused := true
		for _, roster := range rosters {
			if _, admitted := roster.held.Tenant(agentID); admitted {
				refused = false
				break
			}
		}
		if refused {
			return time.Since(published), true
		}
		time.Sleep(200 * time.Microsecond)
	}
	return deadline, false
}

// Three gateways follow the agent log while it churns with other decisions and
// the backbone carries a stream of telemetry-sized records beside it; each
// revocation is timed from the moment the backbone acknowledged it to the moment
// the last of the three refuses the agent, and no roster may go stale meanwhile.
func TestEveryRosterRefusesARevokedAgentWithinTheDeadlineUnderLoad(t *testing.T) {
	addresses := brokers(t)
	topic := compactedAgentTopic(t, addresses)
	publisher, err := broker.NewAgents(broker.Config{Brokers: addresses, Topic: topic, MaxMessageBytes: temporaryCarriage, ClientID: "integration-control"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(publisher.Close)

	const revoked = 100
	var seeded []*agentv1.Admission
	for index := range 300 {
		seeded = append(seeded, admissionOf(fmt.Sprintf("web-%03d", index), agent.Active, 1))
	}
	publishAll(t, publisher, seeded...)

	rosters := []*followingRoster{
		followRoster(t, addresses, topic, time.Second, revocationDeadline),
		followRoster(t, addresses, topic, time.Second, revocationDeadline),
		followRoster(t, addresses, topic, time.Second, revocationDeadline),
	}

	loading, stopLoad := context.WithCancel(context.Background())
	var churned, carried atomic.Int64
	var load sync.WaitGroup
	load.Add(2)
	go func() {
		defer load.Done()
		for revision := uint64(2); loading.Err() == nil; revision++ {
			state := agent.Active
			if revision%2 == 0 {
				state = agent.Disabled
			}
			if publisher.Publish(loading, admissionOf(fmt.Sprintf("churn-%02d", revision%50), state, revision)) == nil {
				churned.Add(1)
			}
		}
	}()
	telemetry := telemetryTopic(t, addresses)
	go func() {
		defer load.Done()
		carried.Store(telemetryLoad(t, loading, addresses, telemetry))
	}()
	time.Sleep(2 * time.Second)

	var took []time.Duration
	for index := range revoked {
		time.Sleep(50 * time.Millisecond)
		agentID := fmt.Sprintf("web-%03d", index)
		publishAll(t, publisher, admissionOf(agentID, agent.Revoked, 2))
		elapsed, refused := refusedWithin(rosters, agentID, revocationDeadline)
		if !refused {
			t.Fatalf("%s was still admitted by a roster %s after its revocation was acknowledged", agentID, revocationDeadline)
		}
		took = append(took, elapsed)
		for position, roster := range rosters {
			if roster.currency.Stale() {
				t.Fatalf("roster %d went stale under load, so its gateway would admit nothing", position)
			}
		}
	}
	stopLoad()
	load.Wait()

	slices.Sort(took)
	share := func(fraction float64) time.Duration { return took[int(fraction*float64(len(took)-1))] }
	t.Logf("%d revocations reached all of 3 rosters: p50 %s, p95 %s, p99 %s, max %s, with %d other decisions and %d records of telemetry carried meanwhile",
		len(took), share(0.5), share(0.95), share(0.99), took[len(took)-1], churned.Load(), carried.Load())
	if churned.Load() < int64(revoked) || carried.Load() == 0 {
		t.Fatalf("the backbone carried %d other decisions and %d records of telemetry, so this was not under load", churned.Load(), carried.Load())
	}
}

func telemetryTopic(t *testing.T, addresses []string) string {
	t.Helper()
	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	admin := kadm.NewClient(client)
	topic := fmt.Sprintf("telemetry.load.%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := admin.CreateTopic(ctx, 3, 1, nil, topic); err != nil {
		t.Fatalf("create topic: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.DeleteTopics(cleanup, topic)
	})
	return topic
}

// Twenty thousand records of an event's size a second, which no compression
// shrinks, until the context ends; it answers how many were acknowledged.
func telemetryLoad(t *testing.T, ctx context.Context, addresses []string, topic string) int64 {
	t.Helper()
	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...), kgo.DefaultProduceTopic(topic),
		kgo.ProducerBatchCompression(kgo.NoCompression()), kgo.MaxBufferedBytes(32<<20))
	if err != nil {
		t.Error(err)
		return 0
	}
	defer client.Close()

	payload := make([]byte, 1<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Error(err)
		return 0
	}
	var carried atomic.Int64
	var inFlight sync.WaitGroup
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for ctx.Err() == nil {
		<-tick.C
		for range 20 {
			inFlight.Add(1)
			client.Produce(ctx, &kgo.Record{Value: payload}, func(_ *kgo.Record, err error) {
				defer inFlight.Done()
				if err == nil {
					carried.Add(1)
				}
			})
		}
	}
	inFlight.Wait()
	return carried.Load()
}

// A roster that stops reading the log while decisions keep arriving cannot
// confirm it holds them, so past its bound its gateway admits nothing; once it
// reads again it is current, and the agent revoked meanwhile is refused.
func TestARosterThatStopsFollowingTheLogIsStaleOncePastItsBound(t *testing.T) {
	addresses := brokers(t)
	topic := compactedAgentTopic(t, addresses)
	publisher, err := broker.NewAgents(broker.Config{Brokers: addresses, Topic: topic, MaxMessageBytes: temporaryCarriage, ClientID: "integration-control"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(publisher.Close)
	publishAll(t, publisher, admissionOf("web-01", agent.Active, 1), admissionOf("web-02", agent.Active, 1))

	roster := followRoster(t, addresses, topic, 200*time.Millisecond, time.Second)
	if roster.currency.Stale() {
		t.Fatal("a roster that replayed the whole log is stale")
	}

	roster.pause()
	stopped := time.Now()
	publishAll(t, publisher, admissionOf("web-01", agent.Revoked, 2))
	for !roster.currency.Stale() {
		if time.Since(stopped) > 3*time.Second {
			t.Fatal("a roster that stopped reading the log while a revocation arrived was still current three seconds later")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, admitted := roster.held.Tenant("web-01"); !admitted {
		t.Fatal("the roster read the revocation it was meant to have missed, so this proves nothing")
	}
	t.Logf("a roster that stopped reading went stale %s after it stopped", time.Since(stopped))

	roster.resume(t)
	resumed := time.Now()
	for roster.currency.Stale() {
		if time.Since(resumed) > 3*time.Second {
			t.Fatal("a roster reading the log again was not current three seconds later")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, admitted := roster.held.Tenant("web-01"); admitted {
		t.Fatal("a roster current again still admits the agent revoked while it was stale")
	}
	if _, admitted := roster.held.Tenant("web-02"); !admitted {
		t.Fatal("a roster current again refuses an agent nobody revoked")
	}
}
