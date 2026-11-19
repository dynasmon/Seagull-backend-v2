package control

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Every agent the registry still admits, by identifier, with the tenant it was
// registered in. An agent it stopped admitting is not part of the fleet: it is
// refused, so it falls silent because it was told to.
type Admitted interface {
	Admitted(ctx context.Context) (map[string]string, error)
}

// What was last heard of each agent asked about, bounded the way Reports is,
// by the agents and the tenants of one read, and light enough to read for a
// whole fleet: when the newest report arrived, what it announced, and whether
// it said the agent was stopping.
type Heard interface {
	Heard(ctx context.Context, agents, tenants []string) (map[string]agentstatus.Heard, error)
}

// How many agents of the fleet are in each liveness, judged at one instant the
// way a listing judges each agent it shows, so the count is what an operator
// reading the whole fleet would have read then. It decides nothing about any
// agent and keeps no state but the count.
type FleetReader struct {
	registry Admitted
	reports  Heard
	metrics  *Metrics
	logger   *slog.Logger
	every    time.Duration
	now      func() time.Time
}

type FleetReaderOptions struct {
	Registry Admitted
	Reports  Heard
	Metrics  *Metrics
	Logger   *slog.Logger
	Every    time.Duration
	Now      func() time.Time
}

func NewFleetReader(options FleetReaderOptions) (*FleetReader, error) {
	switch {
	case options.Registry == nil:
		return nil, errors.New("a fleet reader needs the agents the registry admits")
	case options.Reports == nil:
		return nil, errors.New("a fleet reader needs what agents last reported")
	case options.Metrics == nil:
		return nil, errors.New("a fleet reader needs metrics")
	case options.Logger == nil:
		return nil, errors.New("a fleet reader needs a logger")
	case options.Every <= 0:
		return nil, errors.New("a fleet reader needs a positive interval")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &FleetReader{
		registry: options.Registry,
		reports:  options.Reports,
		metrics:  options.Metrics,
		logger:   options.Logger,
		every:    options.Every,
		now:      options.Now,
	}, nil
}

func (r *FleetReader) Name() string { return "fleet-reader" }

func (r *FleetReader) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.every)
	defer ticker.Stop()

	r.Sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.Sweep(ctx)
		}
	}
}

func (r *FleetReader) Sweep(ctx context.Context) {
	reading, cancel := context.WithTimeout(ctx, r.every)
	defer cancel()

	counted, err := r.count(reading, r.now())
	switch {
	case err != nil && ctx.Err() != nil:
		return
	case err != nil:
		r.metrics.fleetRead("unreadable")
		r.logger.Warn("agent_fleet_unread", slog.String("error", err.Error()))
		return
	}
	r.metrics.fleetCounted(counted)
	r.metrics.fleetRead("read")
}

func (r *FleetReader) count(ctx context.Context, now time.Time) (map[agentv1.Liveness]int, error) {
	admitted, err := r.registry.Admitted(ctx)
	if err != nil {
		return nil, err
	}
	agents := slices.SortedFunc(maps.Keys(admitted), func(a, b string) int {
		return cmp.Or(cmp.Compare(admitted[a], admitted[b]), cmp.Compare(a, b))
	})

	counted := map[agentv1.Liveness]int{}
	for chunk := range slices.Chunk(agents, readingChunk) {
		var tenants []string
		for _, id := range chunk {
			if tenant := admitted[id]; !slices.Contains(tenants, tenant) {
				tenants = append(tenants, tenant)
			}
		}
		heard, err := r.reports.Heard(ctx, chunk, tenants)
		if err != nil {
			return nil, err
		}
		for _, id := range chunk {
			counted[heard[id].Liveness(now)]++
		}
	}
	return counted, nil
}
