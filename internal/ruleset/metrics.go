package ruleset

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

const (
	Applied = "applied"
	Refused = "refused"
)

type Metrics struct {
	info        *prometheus.GaugeVec
	rules       *prometheus.GaugeVec
	loaded      prometheus.Gauge
	reloads     *prometheus.CounterVec
	activations *prometheus.CounterVec
}

// Created once per process and handed to the registry, as the engine does it.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		info: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ruleset",
			Name:      "info",
			Help:      "Identity of the ruleset the process is pinned to.",
		}, []string{"ruleset"}),
		rules: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ruleset",
			Name:      "rules",
			Help:      "Rules the current ruleset holds, by whether they are evaluated.",
		}, []string{"state"}),
		loaded: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ruleset",
			Name:      "loaded_timestamp_seconds",
			Help:      "When the process last changed the ruleset it is pinned to.",
		}),
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ruleset",
			Name:      "reloads_total",
			Help:      "Attempts to read the source again, by what came of them.",
		}, []string{"outcome"}),
		activations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ruleset",
			Name:      "activations_total",
			Help:      "Rulesets this process was asked to run, by whether it could.",
		}, []string{"outcome"}),
	}
	registry.MustRegister(
		instruments.info,
		instruments.rules,
		instruments.loaded,
		instruments.reloads,
		instruments.activations,
	)
	return instruments
}

// One series and not one per ruleset ever loaded: the identity is a label, and
// a label that accumulated would open exactly the cardinality v1 had to close
// after an incident. The reset is what keeps only the current one exposed.
func (m *Metrics) pinned(snapshot *Snapshot, since time.Time) {
	m.info.Reset()
	m.info.WithLabelValues(string(snapshot.ID())).Set(1)
	m.rules.WithLabelValues("held").Set(float64(snapshot.Rules()))
	m.rules.WithLabelValues("running").Set(float64(snapshot.Running()))
	m.loaded.Set(float64(since.UnixNano()) / float64(time.Second))
}

func (m *Metrics) reloaded(outcome string) { m.reloads.WithLabelValues(outcome).Inc() }

func (m *Metrics) activated(outcome string) { m.activations.WithLabelValues(outcome).Inc() }
