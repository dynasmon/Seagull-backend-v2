package control_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type stubAdmitted struct {
	agents map[string]string
	broken error
}

func (s *stubAdmitted) Admitted(ctx context.Context) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.broken != nil {
		return nil, s.broken
	}
	return maps.Clone(s.agents), nil
}

type heardOf struct {
	tenant string
	heard  agentstatus.Heard
}

type stubHeard struct {
	held    map[string]heardOf
	broken  error
	agents  [][]string
	tenants [][]string
}

func (s *stubHeard) Heard(_ context.Context, agents, tenants []string) (map[string]agentstatus.Heard, error) {
	s.agents = append(s.agents, slices.Clone(agents))
	s.tenants = append(s.tenants, slices.Clone(tenants))
	if s.broken != nil {
		return nil, s.broken
	}
	answered := map[string]agentstatus.Heard{}
	for _, id := range agents {
		if one, found := s.held[id]; found && slices.Contains(tenants, one.tenant) {
			answered[id] = one.heard
		}
	}
	return answered, nil
}

func fleetReader(t *testing.T, registry *stubAdmitted, reports *stubHeard, clock time.Time) (*control.FleetReader, *metrics.Registry) {
	t.Helper()
	exported := metrics.New("control-api-fleet")
	reader, err := control.NewFleetReader(control.FleetReaderOptions{
		Registry: registry, Reports: reports, Metrics: control.NewMetrics(exported),
		Logger: slog.New(slog.DiscardHandler), Every: 30 * time.Second, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return reader, exported
}

func counted(t *testing.T, exported *metrics.Registry) map[string]float64 {
	t.Helper()
	read := map[string]float64{}
	for _, liveness := range []string{"unspecified", "active", "late", "silent", "stopped"} {
		read[liveness] = gauged(t, exported, `seagull_control_fleet_agents{liveness="`+liveness+`"}`)
	}
	return read
}

func TestTheFleetIsCountedByLivenessAtTheInstantItIsRead(t *testing.T) {
	clock := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	registry := &stubAdmitted{agents: map[string]string{
		"web-01": "default", "web-02": "default", "web-03": "default", "web-04": "acme", "web-05": "acme", "db-01": "acme",
	}}
	reports := &stubHeard{held: map[string]heardOf{
		"web-01": {"default", agentstatus.Heard{Received: clock.Add(-30 * time.Second), Interval: time.Minute}},
		"web-02": {"default", agentstatus.Heard{Received: clock.Add(-3 * time.Minute), Interval: time.Minute}},
		"web-03": {"default", agentstatus.Heard{Received: clock.Add(-6 * time.Minute), Interval: time.Minute}},
		"web-04": {"acme", agentstatus.Heard{Received: clock.Add(-48 * time.Hour), Interval: time.Minute, Stopping: true}},
		"web-05": {"acme", agentstatus.Heard{Received: clock.Add(-time.Minute), Interval: 30 * time.Second}},
		"old-01": {"default", agentstatus.Heard{Received: clock.Add(-time.Hour), Interval: time.Minute}},
	}}
	reader, exported := fleetReader(t, registry, reports, clock)

	reader.Sweep(context.Background())

	want := map[string]float64{"unspecified": 1, "active": 2, "late": 1, "silent": 1, "stopped": 1}
	if got := counted(t, exported); !maps.Equal(got, want) {
		t.Fatalf("the fleet was counted as %v, and the registry admits six agents counted as %v", got, want)
	}
	if read := gauged(t, exported, `seagull_control_fleet_readings_total{outcome="read"}`); read != 1 {
		t.Fatalf("%v readings are counted as read after one", read)
	}
}

func TestTheFleetIsReadAThousandAgentsAtATimeWithinTheirTenants(t *testing.T) {
	clock := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	registry := &stubAdmitted{agents: map[string]string{}}
	for index := range 2500 {
		registry.agents[fmt.Sprintf("agent-%04d", index)] = []string{"default", "acme", "globex"}[index%3]
	}
	reports := &stubHeard{}
	reader, exported := fleetReader(t, registry, reports, clock)

	reader.Sweep(context.Background())

	asked := map[string]int{}
	for call, chunk := range reports.agents {
		if len(chunk) == 0 || len(chunk) > 1000 {
			t.Fatalf("one read of the status store asked about %d agents", len(chunk))
		}
		var tenants []string
		for _, id := range chunk {
			asked[id]++
			if !slices.Contains(tenants, registry.agents[id]) {
				tenants = append(tenants, registry.agents[id])
			}
		}
		if got := reports.tenants[call]; len(got) != len(tenants) || !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(tenants))) {
			t.Fatalf("a read of agents of %v was scoped to %v", tenants, got)
		}
	}
	if len(reports.agents) != 3 || len(asked) != 2500 {
		t.Fatalf("2500 agents were read in %d reads naming %d of them", len(reports.agents), len(asked))
	}
	for id, times := range asked {
		if times != 1 {
			t.Fatalf("%s was asked about %d times in one reading", id, times)
		}
	}
	if never := gauged(t, exported, `seagull_control_fleet_agents{liveness="unspecified"}`); never != 2500 {
		t.Fatalf("%v of 2500 agents that never reported are counted so", never)
	}
}

func TestAFleetReadingThatFailsKeepsTheCountItLastRead(t *testing.T) {
	clock := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	registry := &stubAdmitted{agents: map[string]string{"web-01": "default", "web-02": "default"}}
	reports := &stubHeard{held: map[string]heardOf{
		"web-01": {"default", agentstatus.Heard{Received: clock.Add(-10 * time.Second), Interval: time.Minute}},
	}}
	reader, exported := fleetReader(t, registry, reports, clock)
	reader.Sweep(context.Background())
	before := counted(t, exported)

	reports.broken = errors.New("the status store is unreachable")
	reader.Sweep(context.Background())
	reports.broken, registry.broken = nil, errors.New("the registry is unreachable")
	reader.Sweep(context.Background())

	if after := counted(t, exported); !maps.Equal(after, before) {
		t.Fatalf("two failed readings moved the count from %v to %v", before, after)
	}
	if unread := gauged(t, exported, `seagull_control_fleet_readings_total{outcome="unreadable"}`); unread != 2 {
		t.Fatalf("%v readings are counted as unreadable after two failed", unread)
	}

	registry.broken = nil
	registry.agents["web-03"] = "default"
	reader.Sweep(context.Background())
	if never := gauged(t, exported, `seagull_control_fleet_agents{liveness="unspecified"}`); never != 2 {
		t.Fatalf("after a reading that succeeded, %v agents that never reported are counted, and two are admitted", never)
	}
}

func TestAReadingAbandonedAsTheProcessStopsIsNoUnreadableFleet(t *testing.T) {
	clock := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	registry := &stubAdmitted{agents: map[string]string{"web-01": "default"}}
	reader, exported := fleetReader(t, registry, &stubHeard{}, clock)
	stopping, stop := context.WithCancel(context.Background())
	stop()

	reader.Sweep(stopping)
	registry.broken = errors.New("the registry is unreachable")
	reader.Sweep(context.Background())

	if unread := gauged(t, exported, `seagull_control_fleet_readings_total{outcome="unreadable"}`); unread != 1 {
		t.Fatalf("%v readings are counted as unreadable, and one failed while another was abandoned as the process stopped", unread)
	}
}

func TestAFleetReaderNeedsWhatItReads(t *testing.T) {
	complete := control.FleetReaderOptions{
		Registry: &stubAdmitted{}, Reports: &stubHeard{}, Metrics: control.NewMetrics(metrics.New("control-api-fleet-options")),
		Logger: slog.New(slog.DiscardHandler), Every: time.Second,
	}
	for name, change := range map[string]func(*control.FleetReaderOptions){
		"no registry":    func(o *control.FleetReaderOptions) { o.Registry = nil },
		"no reports":     func(o *control.FleetReaderOptions) { o.Reports = nil },
		"no metrics":     func(o *control.FleetReaderOptions) { o.Metrics = nil },
		"no logger":      func(o *control.FleetReaderOptions) { o.Logger = nil },
		"no interval":    func(o *control.FleetReaderOptions) { o.Every = 0 },
		"a negative one": func(o *control.FleetReaderOptions) { o.Every = -time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			options := complete
			change(&options)
			if _, err := control.NewFleetReader(options); err == nil {
				t.Fatal("expected the fleet reader to be refused")
			}
		})
	}
	if _, err := control.NewFleetReader(complete); err != nil {
		t.Fatalf("a complete fleet reader was refused: %v", err)
	}
}
