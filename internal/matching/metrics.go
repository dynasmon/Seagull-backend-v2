package matching

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

type Metrics struct {
	triggers    *prometheus.CounterVec
	assessments *prometheus.CounterVec
	decisions   *prometheus.CounterVec
	batches     *prometheus.CounterVec
	sizes       prometheus.Histogram
	settle      *prometheus.HistogramVec
}

// Created once per process and handed to the matcher, as the stores do it.
// Labels are bounded: owners are three groups, scopes and states are the
// contract's enums, outcomes and trigger kinds are words written here.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		triggers: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "matching",
			Name:      "triggers_total",
			Help:      "Records read from the inventory and advisory streams, by what the matcher did with them.",
		}, []string{"kind", "outcome"}),
		assessments: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "matching",
			Name:      "assessments_total",
			Help:      "Evaluations of an asset, by what they covered and what came of them.",
		}, []string{"scope", "outcome"}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "matching",
			Name:      "decisions_total",
			Help:      "Decisions about findings published, by the state they decided.",
		}, []string{"state"}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "matching",
			Name:      "batches_total",
			Help:      "Batches of triggers by whether their decisions were published or had to be decided again.",
		}, []string{"outcome"}),
		sizes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "matching",
			Name:      "batch_records",
			Help:      "Records carried by a batch handed to the matcher.",
			Buckets:   []float64{1, 2, 4, 8, 16, 32, 64, 128},
		}),
		settle: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "matching",
			Name:      "settle_seconds",
			Help:      "Time the matcher waited for the owner of a store to have stored what a batch is about.",
			Buckets:   []float64{0.01, 0.1, 0.5, 1, 5, 30, 120, 600},
		}, []string{"owner"}),
	}
	registry.MustRegister(
		instruments.triggers,
		instruments.assessments,
		instruments.decisions,
		instruments.batches,
		instruments.sizes,
		instruments.settle,
	)
	return instruments
}

func (m *Metrics) observeBatch(records int) { m.sizes.Observe(float64(records)) }

func (m *Metrics) batch(outcome string) { m.batches.WithLabelValues(outcome).Inc() }

func (m *Metrics) trigger(kind, outcome string) { m.triggers.WithLabelValues(kind, outcome).Inc() }

func (m *Metrics) settled(owner string, waited time.Duration) {
	m.settle.WithLabelValues(owner).Observe(waited.Seconds())
}

func (m *Metrics) assessed(scope vulnerabilityv1.Assessment_Scope, outcome string) {
	m.assessments.WithLabelValues(lowered(scope.String(), "SCOPE_"), outcome).Inc()
}

func (m *Metrics) decided(findings []*vulnerabilityv1.Finding) {
	for _, decided := range findings {
		m.decisions.WithLabelValues(lowered(decided.GetState().String(), "FINDING_STATE_")).Inc()
	}
}

func lowered(value, prefix string) string { return strings.ToLower(strings.TrimPrefix(value, prefix)) }
