package agentfindingstore

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	decisions *prometheus.CounterVec
	kinds     *prometheus.CounterVec
	batches   *prometheus.CounterVec
	refusals  *prometheus.CounterVec
	batch     prometheus.Histogram
	write     prometheus.Histogram
}

// Created once per process and handed to the writer, as the other writers do it.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "agentfindingstore",
			Name:      "decisions_total",
			Help:      "Decisions about agent findings by what the writer did with them.",
		}, []string{"outcome"}),
		kinds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "agentfindingstore",
			Name:      "stored_decisions_total",
			Help:      "Decisions about agent findings the writer stored, by the kind of finding and where it stood.",
		}, []string{"kind", "state"}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "agentfindingstore",
			Name:      "batches_total",
			Help:      "Batches of agent finding decisions by whether they became durable or had to be retried.",
		}, []string{"outcome"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "agentfindingstore",
			Name:      "refusals_total",
			Help:      "Records that were not agent finding decisions this build could store, by why.",
		}, []string{"reason"}),
		batch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "agentfindingstore",
			Name:      "batch_records",
			Help:      "Records carried by a batch handed to the agent finding writer.",
			Buckets:   []float64{1, 4, 16, 64, 256, 1024},
		}),
		write: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "agentfindingstore",
			Name:      "write_duration_seconds",
			Help:      "Time spent making a batch of agent finding decisions durable in the store.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
	}
	registry.MustRegister(
		instruments.decisions,
		instruments.kinds,
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

func (m *Metrics) stored(rows []Row, elapsed time.Duration) {
	m.decisions.WithLabelValues("stored").Add(float64(len(rows)))
	for _, row := range rows {
		m.kinds.WithLabelValues(row.Kind, row.State).Inc()
	}
	m.write.Observe(elapsed.Seconds())
}

func (m *Metrics) quarantined(refused []Refused) {
	m.decisions.WithLabelValues("quarantined").Add(float64(len(refused)))
	for _, entry := range refused {
		m.refusals.WithLabelValues(entry.Reason).Inc()
	}
}
