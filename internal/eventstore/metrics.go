package eventstore

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	events   *prometheus.CounterVec
	batches  *prometheus.CounterVec
	refusals *prometheus.CounterVec
	batch    prometheus.Histogram
	write    prometheus.Histogram
}

// Created once per process and handed to the writer, as admission does it.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "eventstore",
			Name:      "events_total",
			Help:      "Records by what the writer did with them.",
		}, []string{"outcome"}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "eventstore",
			Name:      "batches_total",
			Help:      "Batches by whether they became durable or had to be retried.",
		}, []string{"outcome"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "eventstore",
			Name:      "refusals_total",
			Help:      "Quarantined records by why they were refused.",
		}, []string{"reason"}),
		batch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "eventstore",
			Name:      "batch_events",
			Help:      "Records carried by a batch handed to the writer.",
			Buckets:   []float64{1, 10, 100, 500, 1000, 5000, 10000},
		}),
		write: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "eventstore",
			Name:      "write_duration_seconds",
			Help:      "Time spent making a batch durable in the store.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
	}
	registry.MustRegister(
		instruments.events,
		instruments.batches,
		instruments.refusals,
		instruments.batch,
		instruments.write,
	)
	return instruments
}

func (m *Metrics) observeBatch(records int) { m.batch.Observe(float64(records)) }

func (m *Metrics) batchStored() { m.batches.WithLabelValues("stored").Inc() }

func (m *Metrics) batchRetried() { m.batches.WithLabelValues("retried").Inc() }

// A retried batch is written again, so this counts successful writes, not
// distinct events. `batches_total{outcome="retried"}` explains the difference.
func (m *Metrics) stored(events int, elapsed time.Duration) {
	m.events.WithLabelValues("stored").Add(float64(events))
	m.write.Observe(elapsed.Seconds())
}

func (m *Metrics) quarantined(refused []Refused) {
	m.events.WithLabelValues("quarantined").Add(float64(len(refused)))
	for _, entry := range refused {
		m.refusals.WithLabelValues(entry.Reason).Inc()
	}
}
