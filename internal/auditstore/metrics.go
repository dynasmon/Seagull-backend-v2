package auditstore

import (
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	events   *prometheus.CounterVec
	refusals *prometheus.CounterVec
	batches  *prometheus.CounterVec
	batch    prometheus.Histogram
	write    prometheus.Histogram
}

// Created once per process and handed to the writer, as the other writers do it.
// A batch retried as unordered is one the store answered out of the order it
// was asked in: a replicated store read without sequential consistency.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "auditstore",
			Name:      "events_total",
			Help:      "Audit records by what the writer did with them: chained, replayed or duplicate (already on their chain), or quarantined.",
		}, []string{"outcome"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "auditstore",
			Name:      "refusals_total",
			Help:      "Audit records the writer could not chain, by why.",
		}, []string{"reason"}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "auditstore",
			Name:      "batches_total",
			Help:      "Batches of audit records by whether they became durable or had to be retried.",
		}, []string{"outcome"}),
		batch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "auditstore",
			Name:      "batch_records",
			Help:      "Records carried by a batch handed to the audit writer.",
			Buckets:   []float64{1, 4, 16, 64, 256, 1024},
		}),
		write: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "auditstore",
			Name:      "write_duration_seconds",
			Help:      "Time spent appending a batch of audit entries to the store.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
	}
	registry.MustRegister(
		instruments.events,
		instruments.refusals,
		instruments.batches,
		instruments.batch,
		instruments.write,
	)
	return instruments
}

func (m *Metrics) observeBatch(records int) { m.batch.Observe(float64(records)) }

func (m *Metrics) wrote(elapsed time.Duration) { m.write.Observe(elapsed.Seconds()) }

func (m *Metrics) retried(unordered bool) {
	if unordered {
		m.batches.WithLabelValues("unordered").Inc()
		return
	}
	m.batches.WithLabelValues("retried").Inc()
}

func (m *Metrics) stored(result linked, refused []Refused) {
	m.batches.WithLabelValues("stored").Inc()
	m.events.WithLabelValues("chained").Add(float64(len(result.rows)))
	m.events.WithLabelValues("replayed").Add(float64(result.replayed))
	m.events.WithLabelValues("duplicate").Add(float64(result.duplicates))
	m.events.WithLabelValues("quarantined").Add(float64(len(refused) + len(result.misplaced)))
	for _, entry := range slices.Concat(refused, result.misplaced) {
		m.refusals.WithLabelValues(entry.Reason).Inc()
	}
}
