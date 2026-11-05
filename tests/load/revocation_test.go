//go:build load

package load_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
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

func backbone(t *testing.T, step string) {
	t.Helper()
	command := os.Getenv("SEAGULL_TEST_BROKER_" + step)
	if said, err := exec.Command("sh", "-c", command).CombinedOutput(); command == "" || err != nil {
		t.Fatalf("%s the backbone: %v\n%s", step, err, said)
	}
}

func agentLog(t *testing.T, addresses []string) string {
	t.Helper()
	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	topic := fmt.Sprintf("security.agents.load.%d", time.Now().UnixNano())
	compact, forever := "compact", "-1"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin := kadm.NewClient(client)
	if _, err := admin.CreateTopic(ctx, 1, 1, map[string]*string{"cleanup.policy": &compact, "retention.ms": &forever}, topic); err != nil {
		t.Fatalf("create topic: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.DeleteTopics(cleanup, topic)
	})
	return topic
}

func admission(agentID string, state agent.State, revision uint64) *agentv1.Admission {
	return &agentv1.Admission{AgentId: agentID, TenantId: "acme", State: state.Wire(), Revision: revision, ChangedAt: timestamppb.Now()}
}

func publishSoon(t *testing.T, publisher *broker.Agents, record *agentv1.Admission, within time.Duration) time.Time {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := publisher.Publish(ctx, record)
		cancel()
		if err == nil {
			return time.Now()
		}
		if time.Now().After(deadline) {
			t.Fatalf("publish the admission of %s: %v", record.GetAgentId(), err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func awaitRefusal(t *testing.T, held *agent.Roster, agentID string, since time.Time, within time.Duration) time.Duration {
	t.Helper()
	for {
		if _, admitted := held.Tenant(agentID); !admitted {
			return time.Since(since)
		}
		if time.Since(since) > within {
			t.Fatalf("%s was still admitted %s after its revocation was acknowledged", agentID, within)
		}
		time.Sleep(time.Millisecond)
	}
}

// The backbone stops for longer than a gateway's bound: its roster, measured as
// the gateway measures it, goes stale once the bound passes, so the gateway
// would admit nothing; once the backbone is back the roster reads on, is current
// again, and a revocation made then is enforced within the deadline.
func TestARevocationIsEnforcedThroughABackboneOutage(t *testing.T) {
	const every, bound, outage = 5 * time.Second, 30 * time.Second, 45 * time.Second
	addresses := brokers(t)
	if os.Getenv("SEAGULL_TEST_BROKER_STOP") == "" || os.Getenv("SEAGULL_TEST_BROKER_START") == "" {
		t.Skip("set SEAGULL_TEST_BROKER_STOP and SEAGULL_TEST_BROKER_START to the commands that stop and start the backbone")
	}

	topic := agentLog(t, addresses)
	publisher, err := broker.NewAgents(broker.Config{Brokers: addresses, Topic: topic, MaxMessageBytes: 1 << 20, ClientID: "load-control"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(publisher.Close)
	for _, agentID := range []string{"web-01", "web-02", "web-03"} {
		publishSoon(t, publisher, admission(agentID, agent.Active, 1), 30*time.Second)
	}

	reader, err := broker.NewStateLog(broker.Config{Brokers: addresses, Topic: topic, ClientID: "load-roster"}, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	held := agent.NewRoster()
	apply := func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			var decided agentv1.Admission
			if err := proto.Unmarshal(record.Value, &decided); err != nil {
				return err
			}
			if err := held.Apply(&decided); err != nil {
				return err
			}
		}
		return nil
	}
	replayCtx, cancelReplay := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelReplay()
	if err := reader.Replay(replayCtx, apply); err != nil {
		t.Fatal(err)
	}
	currency, err := ingest.NewCurrency(ingest.CurrencyOptions{Log: reader, Every: every, StaleAfter: bound,
		Registry: metrics.New("load-roster"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	currency.Confirm(context.Background())
	running, stop := context.WithCancel(context.Background())
	followed := make(chan error, 1)
	go func() { followed <- reader.Follow(running, apply) }()
	go func() { _ = currency.Run(running) }()
	t.Cleanup(func() { stop(); <-followed })

	before := awaitRefusal(t, held, "web-01", publishSoon(t, publisher, admission("web-01", agent.Revoked, 2), time.Minute), bound)

	backbone(t, "STOP")
	stopped := time.Now()
	t.Cleanup(func() { backbone(t, "START") })
	for !currency.Stale() {
		if time.Since(stopped) > bound+2*every {
			t.Fatalf("the roster was still current %s after the backbone stopped", time.Since(stopped))
		}
		time.Sleep(100 * time.Millisecond)
	}
	wentStale := time.Since(stopped)
	if _, admitted := held.Tenant("web-02"); !admitted {
		t.Fatal("the roster lost an agent nobody revoked while the backbone was away")
	}
	time.Sleep(outage - wentStale)

	backbone(t, "START")
	started := time.Now()
	revoked := publishSoon(t, publisher, admission("web-02", agent.Revoked, 2), 2*time.Minute)
	after := awaitRefusal(t, held, "web-02", revoked, bound)
	for currency.Stale() {
		if time.Since(started) > 2*time.Minute {
			t.Fatal("the roster was not current two minutes after the backbone came back")
		}
		time.Sleep(100 * time.Millisecond)
	}
	current := time.Since(started)

	t.Logf("before the outage a revocation was enforced %s after it was acknowledged; the backbone stopped for %s and the roster went stale %s into it; "+
		"%s after the backbone started the first revocation was acknowledged and enforced %s later, and the roster was current %s after the start",
		before, outage, wentStale, revoked.Sub(started), after, current)
	if _, admitted := held.Tenant("web-03"); !admitted {
		t.Fatal("the roster refuses an agent nobody revoked once the backbone is back")
	}
}
