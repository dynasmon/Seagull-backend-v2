//go:build integration

package integration_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/fleetjudge"
	"github.com/dynasmon/Seagull-backend-v2/internal/listening"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type wholeLog struct{ reader *broker.StateLog }

func (l wholeLog) Replay(ctx context.Context, deliver fleetjudge.Deliver) error {
	return l.reader.Replay(ctx, bridgedToJudge(deliver))
}

func (l wholeLog) Follow(ctx context.Context, deliver fleetjudge.Deliver) error {
	return l.reader.Follow(ctx, bridgedToJudge(deliver))
}

func (l wholeLog) Behind(ctx context.Context) (int64, time.Time, error) { return l.reader.Behind(ctx) }

func bridgedToJudge(deliver fleetjudge.Deliver) broker.Deliver {
	return func(ctx context.Context, records []broker.Record) error {
		converted := make([]fleetjudge.Record, 0, len(records))
		for _, record := range records {
			converted = append(converted, fleetjudge.Record{Partition: record.Partition, Offset: record.Offset, Key: record.Key, Value: record.Value, Timestamp: record.Timestamp})
		}
		return deliver(ctx, converted)
	}
}

type judgeClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *judgeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at }

func (c *judgeClock) set(at time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.at = at }

type judged struct {
	t         *testing.T
	addresses []string
	topics    map[string]string
	clock     *judgeClock
	exported  *metrics.Registry
	judge     *fleetjudge.Judge
	status    *broker.Status
	agents    *broker.Agents
	beacons   *broker.Beacons
	refusals  *broker.Refusals
	logs      map[string]*broker.StateLog
	agentID   string
	silentAt  time.Time
}

func stateLog(t *testing.T, addresses []string, topic string) *broker.StateLog {
	t.Helper()
	reader, err := broker.NewStateLog(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-judge"}, 1_000)
	if err != nil {
		t.Fatalf("read %s: %v", topic, err)
	}
	t.Cleanup(reader.Close)
	return reader
}

// The judge reads real logs on the backbone and decides on a clock the test
// moves, so five intervals of silence take no time to pass.
func judging(t *testing.T) *judged {
	t.Helper()
	addresses := brokers(t)
	j := &judged{
		t: t, addresses: addresses, clock: &judgeClock{at: time.Now().UTC().Truncate(time.Millisecond)},
		exported: metrics.New("integration-fleet-judge"), agentID: agentIdentifier(t),
		topics: map[string]string{
			"status": compactedTopic(t, addresses), "agents": compactedTopic(t, addresses),
			"gateways": compactedTopic(t, addresses), "findings": temporaryTopic(t, addresses),
			"refusals": temporaryTopic(t, addresses),
		},
		logs: map[string]*broker.StateLog{},
	}
	var err error
	if j.status, err = broker.NewStatus(broker.Config{Brokers: addresses, Topic: j.topics["status"], MaxMessageBytes: temporaryCarriage, ClientID: "integration-test"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.status.Close)
	if j.agents, err = broker.NewAgents(broker.Config{Brokers: addresses, Topic: j.topics["agents"], MaxMessageBytes: temporaryCarriage, ClientID: "integration-test"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.agents.Close)
	if j.beacons, err = broker.NewBeacons(broker.Config{Brokers: addresses, Topic: j.topics["gateways"], MaxMessageBytes: temporaryCarriage, ClientID: "integration-test"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.beacons.Close)
	if j.refusals, err = broker.NewRefusals(broker.Config{Brokers: addresses, Topic: j.topics["refusals"], MaxMessageBytes: temporaryCarriage, ClientID: "integration-test"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.refusals.Close)
	return j
}

func (j *judged) report(sequence uint64, arrived time.Time) {
	j.t.Helper()
	report := fixtures.Report{AgentID: j.agentID, Sequence: sequence, At: arrived.Add(-time.Second), Interval: time.Minute}.Status()
	report.Origin.TenantId = "default"
	report.Reception = &eventv1.Reception{IngestTime: timestamppb.New(arrived), Gateway: "gateway-integration", BatchId: "status-" + strconv.FormatUint(sequence, 10)}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := j.status.PublishStatus(ctx, []*agentv1.Status{report}); err != nil {
		j.t.Fatalf("publish a report: %v", err)
	}
}

func (j *judged) start() {
	j.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := j.agents.Publish(ctx, &agentv1.Admission{AgentId: j.agentID, TenantId: "default", State: agentv1.State_STATE_ACTIVE, Revision: 2, ChangedAt: timestamppb.New(j.clock.now())}); err != nil {
		j.t.Fatalf("admit the agent: %v", err)
	}
	decisions, err := broker.NewAgentFindings(broker.Config{Brokers: j.addresses, Topic: j.topics["findings"], MaxMessageBytes: temporaryCarriage, ClientID: "integration-judge"})
	if err != nil {
		j.t.Fatal(err)
	}
	j.t.Cleanup(decisions.Close)
	for name, topic := range j.topics {
		j.logs[name] = stateLog(j.t, j.addresses, topic)
	}
	j.judge, err = fleetjudge.New(fleetjudge.Options{
		Status: wholeLog{j.logs["status"]}, Admissions: wholeLog{j.logs["agents"]}, Beacons: wholeLog{j.logs["gateways"]},
		Findings: wholeLog{j.logs["findings"]}, Refusals: wholeLog{j.logs["refusals"]}, Decisions: decisions, Metrics: fleetjudge.NewMetrics(j.exported),
		Logger: slog.New(slog.DiscardHandler), Every: time.Minute, StaleAfter: 2 * time.Minute, MaxAgents: 1_000,
		Again: 24 * time.Hour, Now: j.clock.now,
	})
	if err != nil {
		j.t.Fatal(err)
	}
	running, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- j.judge.Run(running) }()
	j.t.Cleanup(func() {
		stop()
		if err := <-done; err != nil {
			j.t.Errorf("the judge stopped with %v", err)
		}
	})
	j.until("the judge read the agent's report back", func() bool {
		j.judge.Sweep(context.Background())
		return j.gauge("seagull_fleetjudge_agents") == 1
	})
}

func (j *judged) gauge(series string) float64 {
	recorder := httptest.NewRecorder()
	j.exported.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if value, found := strings.CutPrefix(line, series+" "); found {
			parsed, _ := strconv.ParseFloat(value, 64)
			return parsed
		}
	}
	return -1
}

func (j *judged) until(what string, done func() bool) {
	j.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			j.t.Fatalf("%s never happened", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// What the judge has read of a log it follows, so a sweep judges from all of it.
func (j *judged) caughtUp(names ...string) {
	j.t.Helper()
	for _, name := range names {
		j.until("the judge read "+name+" to its end", func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			behind, _, err := j.logs[name].Behind(ctx)
			return err == nil && behind == 0
		})
	}
}

// A moment of the test: the clock moves there, the gateway says it admits, as
// it would every few seconds, and once the judge heard it, it sweeps.
func (j *judged) at(after time.Duration, admitting bool) {
	j.t.Helper()
	j.clock.set(j.silentAt.Add(after))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := j.beacons.Announce(ctx, listening.Beacon("gateway-integration", j.clock.now(), 5*time.Second, admitting)); err != nil {
		j.t.Fatalf("announce the gateway: %v", err)
	}
	j.caughtUp("gateways")
	j.until("the judge heard the gateway", func() bool {
		j.judge.Sweep(context.Background())
		return j.gauge("seagull_fleetjudge_serving_gateways") == map[bool]float64{true: 1, false: 0}[admitting]
	})
}

func (j *judged) decisions() []*agentv1.Finding {
	j.t.Helper()
	reader := stateLog(j.t, j.addresses, j.topics["findings"])
	var decided []*agentv1.Finding
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := reader.Replay(ctx, func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			var one agentv1.Finding
			if err := proto.Unmarshal(record.Value, &one); err != nil {
				j.t.Fatalf("decode a decision: %v", err)
			}
			decided = append(decided, &one)
		}
		return nil
	}); err != nil {
		j.t.Fatalf("read the decisions: %v", err)
	}
	return decided
}

func TestAnAgentThatStopsReportingIsFoundSilentOnceAndHeardAgainWhenItComesBack(t *testing.T) {
	j := judging(t)
	j.silentAt = j.clock.now()
	j.report(1, j.silentAt)
	j.start()

	j.at(time.Minute, true)
	j.at(6*time.Minute+time.Second, true)
	decided := j.decisions()
	if len(decided) != 1 || decided[0].GetAgentId() != j.agentID || decided[0].GetKind() != agentv1.Finding_KIND_SILENCE ||
		decided[0].GetState() != agentv1.Finding_STATE_OPEN || !decided[0].GetOpenedAt().AsTime().Equal(j.silentAt.Add(5*time.Minute)) {
		t.Fatalf("the backbone holds %v, want one open silence of %s from five minutes after its report", decided, j.agentID)
	}

	j.report(2, j.silentAt.Add(8*time.Minute))
	j.caughtUp("status")
	j.at(8*time.Minute, true)
	decided = j.decisions()
	if len(decided) != 2 || decided[1].GetFindingId() != decided[0].GetFindingId() || decided[1].GetClosure() != agentv1.Finding_CLOSURE_HEARD ||
		!decided[1].GetClosedAt().AsTime().Equal(j.silentAt.Add(8*time.Minute)) {
		t.Fatalf("after the agent reported again the backbone holds %v", decided)
	}
}

func TestNoSilenceIsFoundWhileNoGatewayAdmitsEvenThoughTheBackboneIsUp(t *testing.T) {
	j := judging(t)
	j.silentAt = j.clock.now()
	j.report(1, j.silentAt)
	j.start()

	j.at(time.Minute, false)
	j.at(6*time.Minute+time.Second, false)
	j.at(20*time.Minute, false)
	if decided := j.decisions(); len(decided) != 0 {
		t.Fatalf("a platform whose gateways admitted nothing found %v", decided)
	}
}
