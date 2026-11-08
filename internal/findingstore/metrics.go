package findingstore

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	records     *prometheus.CounterVec
	findings    *prometheus.CounterVec
	assessments *prometheus.CounterVec
	batches     *prometheus.CounterVec
	refusals    *prometheus.CounterVec
	batch       prometheus.Histogram
	write       prometheus.Histogram
}

// Created once per process and handed to the writer, as the other stores do it.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		records: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "findingstore",
			Name:      "records_total",
			Help:      "Finding records by what the finding writer did with them.",
		}, []string{"outcome"}),
		findings: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "findingstore",
			Name:      "findings_total",
			Help:      "Decisions about findings made durable, by the state they decided.",
		}, []string{"state"}),
		assessments: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "findingstore",
			Name:      "assessments_total",
			Help:      "Evaluations of an asset made durable, by what they covered.",
		}, []string{"scope"}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "findingstore",
			Name:      "batches_total",
			Help:      "Batches of finding records by whether they became durable or had to be retried.",
		}, []string{"outcome"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "findingstore",
			Name:      "refusals_total",
			Help:      "Records that were not findings this build could store, by why.",
		}, []string{"reason"}),
		batch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "findingstore",
			Name:      "batch_records",
			Help:      "Records carried by a batch handed to the finding writer.",
			Buckets:   []float64{1, 10, 50, 100, 250, 500, 1000, 5000},
		}),
		write: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "findingstore",
			Name:      "write_duration_seconds",
			Help:      "Time spent making a batch of findings durable in the store.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
	}
	registry.MustRegister(
		instruments.records,
		instruments.findings,
		instruments.assessments,
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
// distinct records. `batches_total{outcome="retried"}` explains the difference.
func (m *Metrics) stored(findings []FindingRow, assessments []AssessmentRow, elapsed time.Duration) {
	m.records.WithLabelValues("stored").Add(float64(len(findings) + len(assessments)))
	for _, row := range findings {
		m.findings.WithLabelValues(row.State).Inc()
	}
	for _, row := range assessments {
		m.assessments.WithLabelValues(row.Scope).Inc()
	}
	m.write.Observe(elapsed.Seconds())
}

func (m *Metrics) quarantined(refused []Refused) {
	m.records.WithLabelValues("quarantined").Add(float64(len(refused)))
	for _, entry := range refused {
		m.refusals.WithLabelValues(entry.Reason).Inc()
	}
}
