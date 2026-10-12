package statusstore

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	reports    *prometheus.CounterVec
	conditions *prometheus.CounterVec
	batches    *prometheus.CounterVec
	refusals   *prometheus.CounterVec
	batch      prometheus.Histogram
	write      prometheus.Histogram
}

// Created once per process and handed to the projector, as the writers do it.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		reports: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statusstore",
			Name:      "reports_total",
			Help:      "Status reports by what the status projector did with them.",
		}, []string{"outcome"}),
		conditions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statusstore",
			Name:      "report_conditions_total",
			Help:      "Status reports folded into the newest of their agent, by the condition the agent said it was in.",
		}, []string{"condition"}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statusstore",
			Name:      "batches_total",
			Help:      "Batches of status reports by whether they became durable or had to be retried.",
		}, []string{"outcome"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statusstore",
			Name:      "refusals_total",
			Help:      "Records that were not status reports this build could store, by why.",
		}, []string{"reason"}),
		batch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statusstore",
			Name:      "batch_records",
			Help:      "Records carried by a batch handed to the status projector.",
			Buckets:   []float64{1, 4, 16, 64, 256, 1024},
		}),
		write: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statusstore",
			Name:      "write_duration_seconds",
			Help:      "Time spent making a batch of status reports durable in the store.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
	}
	registry.MustRegister(
		instruments.reports,
		instruments.conditions,
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
	m.reports.WithLabelValues("stored").Add(float64(len(rows)))
	for _, row := range rows {
		m.conditions.WithLabelValues(row.Condition).Inc()
	}
	m.write.Observe(elapsed.Seconds())
}

func (m *Metrics) quarantined(refused []Refused) {
	m.reports.WithLabelValues("quarantined").Add(float64(len(refused)))
	for _, entry := range refused {
		m.refusals.WithLabelValues(entry.Reason).Inc()
	}
}
