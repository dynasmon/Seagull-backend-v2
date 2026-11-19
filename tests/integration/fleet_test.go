//go:build integration

package integration_test

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
	"github.com/dynasmon/Seagull-backend-v2/internal/statusstore"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func reportedAs(owner string, report fixtures.Report, at time.Time) statusstore.Row {
	status := report.Status()
	status.Origin.TenantId = owner
	status.Reception = &eventv1.Reception{IngestTime: timestamppb.New(at), Gateway: "gateway-integration", BatchId: fmt.Sprintf("status-%d", report.Sequence)}
	published, err := proto.Marshal(status)
	if err != nil {
		panic(err)
	}
	return statusstore.Project(status, published)
}

func binding(at time.Time) agent.Move {
	return agent.Move{Identity: &agentv1.Identity{}, Actor: "it-authority", At: at}
}

func registered(t *testing.T, registry *postgres.Agents, owner string, moves ...agent.Move) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	agentID := agentIdentifier(t)
	if _, err := registry.Register(ctx, &agentv1.Registration{AgentId: agentID, TenantId: owner}, "it-operator", time.Now().UTC()); err != nil {
		t.Fatalf("register %s: %v", agentID, err)
	}
	for _, move := range moves {
		if move.Identity != nil {
			move.Identity = certificateFor(t, agentID, move.At)
		}
		if _, err := registry.Move(ctx, agentID, []string{owner}, move); err != nil {
			t.Fatalf("move %s: %v", agentID, err)
		}
	}
	return agentID
}

func TestEveryAgentTheRegistryAdmitsIsReadWithTheTenantItWasRegisteredIn(t *testing.T) {
	registry := migratedAlertStore(t, alertStoreAddress(t)).Agents()
	owner, elsewhere := tenant(t), tenant(t)
	at := time.Now().UTC().Truncate(time.Millisecond)

	pending := registered(t, registry, owner)
	bound := registered(t, registry, elsewhere, binding(at))
	disabled := registered(t, registry, owner, agent.Move{To: agent.Disabled, Note: "on leave", Actor: "it-operator", At: at})
	revoked := registered(t, registry, owner, agent.Move{To: agent.Revoked, Note: "the key leaked", Actor: "it-operator", At: at})
	retired := registered(t, registry, elsewhere, agent.Move{To: agent.Decommissioned, Note: "gone", Actor: "it-operator", At: at})

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admitted, err := registry.Admitted(ctx)
	if err != nil {
		t.Fatalf("read the agents the registry admits: %v", err)
	}
	if admitted[pending] != owner || admitted[bound] != elsewhere {
		t.Fatalf("a pending agent of %s reads as of %q and an active one of %s as of %q", owner, admitted[pending], elsewhere, admitted[bound])
	}
	for _, refused := range []string{disabled, revoked, retired} {
		if tenant, found := admitted[refused]; found {
			t.Fatalf("%s, which the registry no longer admits, was read as an agent of %s", refused, tenant)
		}
	}
}

func TestWhatWasLastHeardOfEachAgentIsReadWithinTheTenantsAsked(t *testing.T) {
	address := storeAddress(t)
	store := migratedStatusStore(t, address)
	owner, elsewhere := tenant(t), tenant(t)
	talkative, stopping, foreign, quiet := agentIdentifier(t), agentIdentifier(t), agentIdentifier(t), agentIdentifier(t)

	now := time.Now().UTC().Truncate(time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Store(ctx, []statusstore.Row{
		reportedAs(owner, fixtures.Report{AgentID: talkative, Sequence: 2, At: now.Add(-time.Minute), Interval: 5 * time.Minute}, now.Add(-time.Minute)),
		reportedAs(owner, fixtures.Report{AgentID: talkative, Sequence: 1, At: now.Add(-3 * time.Minute), Interval: time.Minute}, now.Add(-3*time.Minute)),
		reportedAs(owner, fixtures.Report{AgentID: stopping, Sequence: 9, At: now.Add(-time.Hour), Interval: 30 * time.Second,
			Condition: agentv1.Status_CONDITION_STOPPED}, now.Add(-time.Hour)),
		reportedAs(elsewhere, fixtures.Report{AgentID: foreign, Sequence: 1, At: now, Interval: time.Minute}, now),
	}); err != nil {
		t.Fatalf("store the reports: %v", err)
	}

	heard, err := liveness(t, address, 720*time.Hour).Heard(ctx, []string{talkative, stopping, foreign, quiet}, []string{owner})
	if err != nil {
		t.Fatalf("read what agents last reported: %v", err)
	}
	want := map[string]agentstatus.Heard{
		talkative: {Received: now.Add(-time.Minute), Interval: 5 * time.Minute},
		stopping:  {Received: now.Add(-time.Hour), Interval: 30 * time.Second, Stopping: true},
	}
	if len(heard) != len(want) {
		t.Fatalf("read what %d agents last reported, and two reported within %s: %+v", len(heard), owner, heard)
	}
	for agentID, expected := range want {
		got := heard[agentID]
		if !got.Received.Equal(expected.Received) || got.Interval != expected.Interval || got.Stopping != expected.Stopping {
			t.Errorf("%s was last heard as %+v, and %+v was stored newest", agentID, got, expected)
		}
	}
}

func scraped(t *testing.T, registry *metrics.Registry, series string) float64 {
	t.Helper()
	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	lines := bufio.NewScanner(strings.NewReader(recorder.Body.String()))
	for lines.Scan() {
		if value, found := strings.CutPrefix(lines.Text(), series+" "); found {
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil {
				t.Fatal(err)
			}
			return parsed
		}
	}
	t.Fatalf("%s is not exported", series)
	return 0
}

func TestTheFleetIsCountedFromWhatTheRegistryAdmitsAndWhatTheAgentsLastReported(t *testing.T) {
	address := storeAddress(t)
	store := migratedStatusStore(t, address)
	registry := migratedAlertStore(t, alertStoreAddress(t)).Agents()
	owner := tenant(t)
	clock := time.Now().UTC().Truncate(time.Millisecond)

	exported := metrics.New("integration-fleet")
	reader, err := control.NewFleetReader(control.FleetReaderOptions{
		Registry: registry, Reports: liveness(t, address, 720*time.Hour), Metrics: control.NewMetrics(exported),
		Logger: slog.New(slog.DiscardHandler), Every: time.Minute, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	livenesses := []string{"unspecified", "active", "late", "silent", "stopped"}
	count := func() map[string]float64 {
		reader.Sweep(context.Background())
		read := map[string]float64{}
		for _, liveness := range livenesses {
			read[liveness] = scraped(t, exported, `seagull_control_fleet_agents{liveness="`+liveness+`"}`)
		}
		return read
	}
	before := count()

	active, late, silent, stopped := registered(t, registry, owner, binding(clock)), registered(t, registry, owner, binding(clock)),
		registered(t, registry, owner, binding(clock)), registered(t, registry, owner, binding(clock))
	registered(t, registry, owner)
	disabled := registered(t, registry, owner, agent.Move{To: agent.Disabled, Note: "on leave", Actor: "it-operator", At: clock})

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Store(ctx, []statusstore.Row{
		reportedAs(owner, fixtures.Report{AgentID: active, At: clock.Add(-30 * time.Second)}, clock.Add(-30*time.Second)),
		reportedAs(owner, fixtures.Report{AgentID: late, At: clock.Add(-4 * time.Minute)}, clock.Add(-4*time.Minute)),
		reportedAs(owner, fixtures.Report{AgentID: silent, At: clock.Add(-6 * time.Minute)}, clock.Add(-6*time.Minute)),
		reportedAs(owner, fixtures.Report{AgentID: stopped, At: clock.Add(-time.Hour), Condition: agentv1.Status_CONDITION_STOPPED}, clock.Add(-time.Hour)),
		reportedAs(owner, fixtures.Report{AgentID: disabled, At: clock.Add(-time.Hour)}, clock.Add(-time.Hour)),
	}); err != nil {
		t.Fatalf("store the reports: %v", err)
	}
	after := count()

	for _, liveness := range livenesses {
		if grew := after[liveness] - before[liveness]; grew != 1 {
			t.Errorf("registering one agent %s moved that count by %v: before %v, after %v", liveness, grew, before, after)
		}
	}
	if read := scraped(t, exported, `seagull_control_fleet_readings_total{outcome="read"}`); read != 2 {
		t.Fatalf("%v readings are counted as read after two", read)
	}
}

func TestWhatACountHearsOfAnAgentIsTheReportAListingShows(t *testing.T) {
	address := storeAddress(t)
	store := migratedStatusStore(t, address)
	owner, elsewhere := tenant(t), tenant(t)
	both, stopping, once := agentIdentifier(t), agentIdentifier(t), agentIdentifier(t)

	now := time.Now().UTC().Truncate(time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Store(ctx, []statusstore.Row{
		reportedAs(owner, fixtures.Report{AgentID: both, Sequence: 4, At: now.Add(-time.Hour), Interval: time.Minute}, now.Add(-time.Hour)),
		reportedAs(elsewhere, fixtures.Report{AgentID: both, Sequence: 5, At: now.Add(-time.Minute), Interval: 2 * time.Minute}, now.Add(-time.Minute)),
		reportedAs(elsewhere, fixtures.Report{AgentID: stopping, Sequence: 7, At: now.Add(-2 * time.Hour), Interval: 15 * time.Second,
			Condition: agentv1.Status_CONDITION_STOPPED}, now.Add(-2*time.Hour)),
		reportedAs(owner, fixtures.Report{AgentID: once, Sequence: 1, At: now.Add(-10 * time.Second), Interval: time.Hour}, now.Add(-10*time.Second)),
	}); err != nil {
		t.Fatalf("store the reports: %v", err)
	}

	reader := liveness(t, address, 720*time.Hour)
	agents, tenants := []string{both, stopping, once}, []string{owner, elsewhere}
	listed, err := reader.Newest(ctx, agents, tenants)
	if err != nil {
		t.Fatalf("read what agents last reported: %v", err)
	}
	heard, err := reader.Heard(ctx, agents, tenants)
	if err != nil {
		t.Fatalf("read when agents last reported: %v", err)
	}
	if len(listed) != 3 || len(heard) != 3 {
		t.Fatalf("a listing read %d agents and a count heard %d, and three reported", len(listed), len(heard))
	}
	for _, agentID := range agents {
		shown := listed[agentID]
		for _, after := range []time.Duration{0, 3 * time.Minute, 30 * time.Minute, 3 * time.Hour} {
			if got, want := heard[agentID].Liveness(now.Add(after)), shown.Liveness(now.Add(after)); got != want {
				t.Errorf("%s later, %s is %s to a count and %s to a listing", after, agentID, got, want)
			}
		}
		if !heard[agentID].Received.Equal(shown.Received) {
			t.Errorf("a count heard %s at %s, and a listing shows the report received at %s", agentID, heard[agentID].Received, shown.Received)
		}
	}
	if heard[both].Received != now.Add(-time.Minute) {
		t.Fatalf("an agent two tenants hold a report of is heard as of %s, and the newest arrived at %s", heard[both].Received, now.Add(-time.Minute))
	}
}
