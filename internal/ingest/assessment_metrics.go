package ingest

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/assessment"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

// Counted apart from every other stream, and by what checks found rather than
// by agent or by check: the outcome is a closed set, so how many failures an
// estate reports is bounded however many checks its policies name.
type AssessmentMetrics struct {
	batches     *prometheus.CounterVec
	assessments *prometheus.CounterVec
	results     *prometheus.CounterVec
	rejections  *prometheus.CounterVec
	publish     prometheus.Histogram
	lag         prometheus.Histogram
}

func NewAssessmentMetrics(registry *metrics.Registry) *AssessmentMetrics {
	instruments := &AssessmentMetrics{
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "assessment_batches_total",
			Help:      "Assessment batches by admission outcome.",
		}, []string{"outcome"}),
		assessments: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "assessments_total",
			Help:      "Assessments by admission outcome.",
		}, []string{"outcome"}),
		results: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "assessment_results_total",
			Help:      "Results of admitted assessments by what the check found.",
		}, []string{"outcome"}),
		rejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "assessment_rejections_total",
			Help:      "Rejected assessment batches by reason.",
		}, []string{"reason"}),
		publish: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "assessment_publish_duration_seconds",
			Help:      "Time spent making an assessment batch durable in the backbone.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
		lag: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "assessment_lag_seconds",
			Help:      "Distance between the time an agent finished an assessment and the time the platform accepted it.",
			Buckets:   []float64{1, 30, 300, 3600, 21600, 86400, 604800},
		}),
	}
	registry.MustRegister(
		instruments.batches,
		instruments.assessments,
		instruments.results,
		instruments.rejections,
		instruments.publish,
		instruments.lag,
	)
	return instruments
}

func (m *AssessmentMetrics) batchAccepted(assessments int, elapsed time.Duration) {
	m.batches.WithLabelValues("accepted").Inc()
	m.assessments.WithLabelValues("accepted").Add(float64(assessments))
	m.publish.Observe(elapsed.Seconds())
}

func (m *AssessmentMetrics) batchRejected(reason string) {
	m.batches.WithLabelValues("rejected").Inc()
	m.rejections.WithLabelValues(reason).Inc()
}

func (m *AssessmentMetrics) batchUnavailable(assessments int) {
	m.batches.WithLabelValues("unavailable").Inc()
	m.assessments.WithLabelValues("unavailable").Add(float64(assessments))
}

func (m *AssessmentMetrics) observe(received time.Time, assessed *assessmentv1.Assessment) {
	for _, result := range assessed.GetResults() {
		m.results.WithLabelValues(assessment.OutcomeName(result.GetOutcome())).Inc()
	}
	if finished := assessed.GetAssessedAt(); finished != nil {
		m.lag.Observe(received.Sub(finished.AsTime()).Seconds())
	}
}
