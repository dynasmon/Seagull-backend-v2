package assessmentstore

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	assessments *prometheus.CounterVec
	results     *prometheus.CounterVec
	batches     *prometheus.CounterVec
	refusals    *prometheus.CounterVec
	batch       prometheus.Histogram
	write       prometheus.Histogram
}

// Created once per process and handed to the projector, as the writers do it.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		assessments: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "assessmentstore",
			Name:      "assessments_total",
			Help:      "Assessments by what the assessment projector did with them.",
		}, []string{"outcome"}),
		results: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "assessmentstore",
			Name:      "results_total",
			Help:      "Results of stored assessments, by what the check found.",
		}, []string{"outcome"}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "assessmentstore",
			Name:      "batches_total",
			Help:      "Batches of assessments by whether they became durable or had to be retried.",
		}, []string{"outcome"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "assessmentstore",
			Name:      "refusals_total",
			Help:      "Records that were not assessments this build could store, by why.",
		}, []string{"reason"}),
		batch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "assessmentstore",
			Name:      "batch_records",
			Help:      "Records carried by a batch handed to the assessment projector.",
			Buckets:   []float64{1, 4, 16, 64, 256, 1024},
		}),
		write: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "assessmentstore",
			Name:      "write_duration_seconds",
			Help:      "Time spent making a batch of assessments durable in the store.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
	}
	registry.MustRegister(
		instruments.assessments,
		instruments.results,
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
	m.assessments.WithLabelValues("stored").Add(float64(len(rows)))
	for _, row := range rows {
		for outcome, count := range map[string]uint32{
			"pass": row.Passed, "fail": row.Failed, "error": row.Errors,
			"unsupported": row.Unsupported, "not_applicable": row.NotApplicable,
		} {
			m.results.WithLabelValues(outcome).Add(float64(count))
		}
	}
	m.write.Observe(elapsed.Seconds())
}

func (m *Metrics) quarantined(refused []Refused) {
	m.assessments.WithLabelValues("quarantined").Add(float64(len(refused)))
	for _, entry := range refused {
		m.refusals.WithLabelValues(entry.Reason).Inc()
	}
}
