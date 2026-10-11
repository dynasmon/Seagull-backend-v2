package ingest

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Counted apart from telemetry and inventory, and by what agents say of
// themselves rather than by agent: the condition is a closed set, so how many
// reports a fleet sends saying it is degraded is bounded however large it grows.
type StatusMetrics struct {
	batches    *prometheus.CounterVec
	reports    *prometheus.CounterVec
	conditions *prometheus.CounterVec
	rejections *prometheus.CounterVec
	publish    prometheus.Histogram
	lag        prometheus.Histogram
}

func NewStatusMetrics(registry *metrics.Registry) *StatusMetrics {
	instruments := &StatusMetrics{
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "status_batches_total",
			Help:      "Status batches by admission outcome.",
		}, []string{"outcome"}),
		reports: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "status_reports_total",
			Help:      "Status reports by admission outcome.",
		}, []string{"outcome"}),
		conditions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "status_report_conditions_total",
			Help:      "Admitted status reports by the condition the agent said it was in.",
		}, []string{"condition"}),
		rejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "status_rejections_total",
			Help:      "Rejected status batches by reason.",
		}, []string{"reason"}),
		publish: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "status_publish_duration_seconds",
			Help:      "Time spent making a status batch durable in the backbone.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
		lag: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "status_lag_seconds",
			Help:      "Distance between the time an agent wrote a report and the time the platform accepted it.",
			Buckets:   []float64{1, 5, 30, 120, 600, 3600},
		}),
	}
	registry.MustRegister(
		instruments.batches,
		instruments.reports,
		instruments.conditions,
		instruments.rejections,
		instruments.publish,
		instruments.lag,
	)
	return instruments
}

func (m *StatusMetrics) batchAccepted(reports int, elapsed time.Duration) {
	m.batches.WithLabelValues("accepted").Inc()
	m.reports.WithLabelValues("accepted").Add(float64(reports))
	m.publish.Observe(elapsed.Seconds())
}

func (m *StatusMetrics) batchRejected(reason string) {
	m.batches.WithLabelValues("rejected").Inc()
	m.rejections.WithLabelValues(reason).Inc()
}

func (m *StatusMetrics) batchUnavailable(reports int) {
	m.batches.WithLabelValues("unavailable").Inc()
	m.reports.WithLabelValues("unavailable").Add(float64(reports))
}

func (m *StatusMetrics) observe(received time.Time, report *agentv1.Status) {
	m.conditions.WithLabelValues(agentstatus.ConditionName(report.GetCondition())).Inc()
	if written := report.GetReportedAt(); written != nil {
		m.lag.Observe(received.Sub(written.AsTime()).Seconds())
	}
}
