package ingest

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

const CodeRosterStale = "roster_stale"

// The log a gateway's copy of the registry's decisions is followed from, asked
// how many records it holds that the copy has not applied, and when the newest
// one the copy applied was written.
type Followed interface {
	Behind(ctx context.Context) (int64, time.Time, error)
}

// Whether the copy is recent enough to admit by. Past its bound the copy might
// still admit an agent the registry has since revoked, so the gateway admits
// nothing until it is confirmed again: a batch kept in an agent's spool is
// delayed, never lost, and a revoked agent is never let in for want of news.
type Currency struct {
	log        Followed
	every      time.Duration
	staleAfter time.Duration
	logger     *slog.Logger
	now        func() time.Time
	started    time.Time

	confirmed atomic.Int64
	newest    atomic.Int64
	stale     atomic.Bool

	behind prometheus.Gauge
	checks *prometheus.CounterVec
}

type CurrencyOptions struct {
	Log        Followed
	Every      time.Duration
	StaleAfter time.Duration
	Registry   *metrics.Registry
	Logger     *slog.Logger
	Now        func() time.Time
}

func NewCurrency(options CurrencyOptions) (*Currency, error) {
	switch {
	case options.Log == nil:
		return nil, errors.New("a gateway confirms its roster against the log it follows, and was given none")
	case options.Every <= 0:
		return nil, errors.New("a gateway confirms its roster at a positive interval")
	case options.StaleAfter < 2*options.Every:
		return nil, errors.New("a roster is stale only after at least two confirmations were missed")
	case options.Registry == nil || options.Logger == nil:
		return nil, errors.New("a gateway reports how current its roster is, and was given nowhere to")
	}
	if options.Now == nil {
		options.Now = time.Now
	}

	c := &Currency{
		log:        options.Log,
		every:      options.Every,
		staleAfter: options.StaleAfter,
		logger:     options.Logger,
		now:        options.Now,
		started:    options.Now(),
		behind: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "roster_behind_records",
			Help:      "Records of the agent log the roster had not applied when it last asked.",
		}),
		checks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "roster_checks_total",
			Help:      "Times the roster was measured against the agent log, by what was found.",
		}, []string{"outcome"}),
	}
	c.stale.Store(true)
	for _, outcome := range []string{"current", "behind", "unreachable"} {
		c.checks.WithLabelValues(outcome)
	}
	bound := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metrics.Namespace,
		Subsystem: "ingest",
		Name:      "roster_stale_after_seconds",
		Help:      "How long the roster may go unconfirmed before the gateway admits nothing.",
	})
	bound.Set(options.StaleAfter.Seconds())
	options.Registry.MustRegister(c.behind, c.checks, bound,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "roster_confirmed_age_seconds",
			Help:      "Time since the roster was last found to hold every decision the agent log held.",
		}, func() float64 { return c.age().Seconds() }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "roster_applied_age_seconds",
			Help:      "Time since the newest decision the roster applied was written to the agent log.",
		}, func() float64 {
			if newest := c.newest.Load(); newest > 0 {
				return c.now().Sub(time.Unix(0, newest)).Seconds()
			}
			return 0
		}),
	)
	return c, nil
}

func (c *Currency) Name() string { return "agent-roster-currency" }

func (c *Currency) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.Confirm(ctx)
		}
	}
}

// Confirm asks the log once. The roster is current as of the moment it asked
// when the log held nothing it had not applied, never as of when the answer came.
func (c *Currency) Confirm(ctx context.Context) {
	asked := c.now()
	within, cancel := context.WithTimeout(ctx, c.every)
	behind, newest, err := c.log.Behind(within)
	cancel()

	switch {
	case err != nil:
		c.checks.WithLabelValues("unreachable").Inc()
	case behind > 0:
		c.checks.WithLabelValues("behind").Inc()
		c.behind.Set(float64(behind))
	default:
		c.checks.WithLabelValues("current").Inc()
		c.behind.Set(0)
		c.confirmed.Store(asked.UnixNano())
	}
	if !newest.IsZero() {
		c.newest.Store(newest.UnixNano())
	}

	stale := c.Stale()
	if was := c.stale.Swap(stale); was == stale {
		return
	}
	if stale {
		attributes := []any{slog.Duration("confirmed_ago", c.age()), slog.Int64("behind", behind)}
		if err != nil {
			attributes = append(attributes, slog.String("error", err.Error()))
		}
		c.logger.Warn("agent_roster_stale", attributes...)
		return
	}
	c.logger.Info("agent_roster_current")
}

func (c *Currency) Stale() bool {
	return c.confirmed.Load() == 0 || c.age() > c.staleAfter
}

func (c *Currency) age() time.Duration {
	if confirmed := c.confirmed.Load(); confirmed > 0 {
		return c.now().Sub(time.Unix(0, confirmed))
	}
	return c.now().Sub(c.started)
}
