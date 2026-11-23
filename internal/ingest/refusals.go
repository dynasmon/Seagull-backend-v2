package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Where a gateway says what it refused, for the platform to judge what the
// refusals of one agent amount to. Refusing never waits on it.
type RefusalPublisher interface {
	PublishRefusals(ctx context.Context, refused []*agentv1.Refusal) error
}

type RefusalsOptions struct {
	Gateway   string
	Publisher RefusalPublisher
	Every     time.Duration
	Most      int
	Registry  *metrics.Registry
	Logger    *slog.Logger
}

// What a gateway refused and has not yet published, one record per agent and
// certificate in force, bounded by Most: a holder of a key asking as fast as it
// likes costs one record each time the gateway publishes, and a refusal beyond
// the bound is counted rather than held.
type Refusals struct {
	gateway   string
	publisher RefusalPublisher
	every     time.Duration
	most      int
	logger    *slog.Logger
	outcomes  *prometheus.CounterVec

	mu       sync.Mutex
	gathered map[string]*agentv1.Refusal
	flushing sync.Mutex
}

func NewRefusals(options RefusalsOptions) (*Refusals, error) {
	switch {
	case options.Gateway == "" || len(options.Gateway) > event.MaxGatewayLength:
		return nil, fmt.Errorf("a gateway names itself in what it refused in 1 to %d bytes", event.MaxGatewayLength)
	case options.Publisher == nil:
		return nil, errors.New("a gateway says what it refused, and was given nowhere to")
	case options.Every <= 0 || options.Most <= 0:
		return nil, errors.New("a gateway publishes what it refused at a positive interval, and holds a positive number of records")
	case options.Registry == nil || options.Logger == nil:
		return nil, errors.New("a gateway reports what it refused, and was given nowhere to")
	}

	outcomes := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: "ingest",
		Name:      "refusals_total",
		Help:      "Refusals of a replaced certificate, by whether the backbone took the record carrying them or the gateway held too many to keep them.",
	}, []string{"outcome"})
	for _, outcome := range []string{"published", "dropped"} {
		outcomes.WithLabelValues(outcome)
	}
	options.Registry.MustRegister(outcomes)

	return &Refusals{
		gateway:   options.Gateway,
		publisher: options.Publisher,
		every:     options.Every,
		most:      options.Most,
		logger:    options.Logger,
		outcomes:  outcomes,
		gathered:  map[string]*agentv1.Refusal{},
	}, nil
}

func (r *Refusals) Name() string { return "agent-refusals" }

func (r *Refusals) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			stopping, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.every)
			defer cancel()
			_ = r.Flush(stopping)
			return nil
		case <-ticker.C:
			_ = r.Flush(ctx)
		}
	}
}

func (r *Refusals) refused(agentID, tenant string, held agentidentity.Held, route string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gather(agentidentity.Refused(agentID, tenant, held, route, r.gateway, at))
}

func (r *Refusals) gather(refused *agentv1.Refusal) {
	key := refused.GetAgentId() + "\x00" + refused.GetFingerprintSha256()
	held, known := r.gathered[key]
	if !known {
		if len(r.gathered) >= r.most {
			r.outcomes.WithLabelValues("dropped").Add(float64(refused.GetRefusals()))
			return
		}
		r.gathered[key] = refused
		return
	}
	held.Refusals += refused.GetRefusals()
	held.Revision = max(held.GetRevision(), refused.GetRevision())
	if refused.GetFirstRefusedAt().AsTime().Before(held.GetFirstRefusedAt().AsTime()) {
		held.FirstRefusedAt = refused.GetFirstRefusedAt()
	}
	if !refused.GetLastRefusedAt().AsTime().Before(held.GetLastRefusedAt().AsTime()) {
		held.LastRefusedAt, held.Use = refused.GetLastRefusedAt(), refused.GetUse()
	}
}

// Publishes what was gathered since the last flush. A record the backbone did
// not take is gathered again with whatever arrived meanwhile, so the next flush
// carries it; only what the bound turns away is lost, and it is counted.
func (r *Refusals) Flush(ctx context.Context) error {
	r.flushing.Lock()
	defer r.flushing.Unlock()

	r.mu.Lock()
	taken := r.gathered
	r.gathered = map[string]*agentv1.Refusal{}
	r.mu.Unlock()
	if len(taken) == 0 {
		return nil
	}

	keys := make([]string, 0, len(taken))
	for key := range taken {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	records := make([]*agentv1.Refusal, 0, len(keys))
	for _, key := range keys {
		records = append(records, taken[key])
	}

	within, cancel := context.WithTimeout(ctx, r.every)
	defer cancel()
	if err := r.publisher.PublishRefusals(within, records); err != nil {
		r.mu.Lock()
		for _, record := range records {
			kept, _ := proto.Clone(record).(*agentv1.Refusal)
			r.gather(kept)
		}
		r.mu.Unlock()
		r.logger.Warn("agent_refusals_unpublished", slog.Int("records", len(records)), slog.String("error", err.Error()))
		return err
	}
	for _, record := range records {
		r.outcomes.WithLabelValues("published").Add(float64(record.GetRefusals()))
		r.logger.Warn("agent_certificate_refused",
			slog.String("agent_id", record.GetAgentId()),
			slog.String("tenant_id", record.GetTenantId()),
			slog.String("route", record.GetUse().GetRoute()),
			slog.Uint64("refusals", record.GetRefusals()),
			slog.Time("first_refused_at", record.GetFirstRefusedAt().AsTime()),
			slog.Time("last_refused_at", record.GetLastRefusedAt().AsTime()),
		)
	}
	return nil
}
