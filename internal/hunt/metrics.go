package hunt

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	queries  *prometheus.CounterVec
	refusals *prometheus.CounterVec
	page     *prometheus.HistogramVec
	answer   *prometheus.HistogramVec
}

// Nothing here is labelled by tenant, caller or field: a query plane sees who is
// asking and what they asked about, and a label is the one place that leaks into
// a metrics endpoint that has no scope of its own.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "hunt",
			Name:      "queries_total",
			Help:      "Questions asked of the store, by dataset and how they ended.",
		}, []string{"dataset", "outcome"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "hunt",
			Name:      "refusals_total",
			Help:      "Questions the query plane would not put to the store, by why.",
		}, []string{"reason"}),
		page: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "hunt",
			Name:      "page_records",
			Help:      "Records carried by one page of an answer.",
			Buckets:   []float64{0, 1, 10, 50, 100, 250, 500},
		}, []string{"dataset"}),
		answer: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "hunt",
			Name:      "answer_duration_seconds",
			Help:      "Time the store spent answering one question.",
			Buckets:   []float64{0.01, 0.05, 0.25, 1, 5, 15, 30},
		}, []string{"dataset"}),
	}
	registry.MustRegister(instruments.queries, instruments.refusals, instruments.page, instruments.answer)
	return instruments
}

func (m *Metrics) answered(dataset Dataset, records int, elapsed time.Duration) {
	m.queries.WithLabelValues(string(dataset), "answered").Inc()
	m.page.WithLabelValues(string(dataset)).Observe(float64(records))
	m.answer.WithLabelValues(string(dataset)).Observe(elapsed.Seconds())
}

func (m *Metrics) refused(dataset Dataset, reason string) {
	m.queries.WithLabelValues(string(dataset), "refused").Inc()
	m.refusals.WithLabelValues(reason).Inc()
}

func (m *Metrics) failed(dataset Dataset, elapsed time.Duration) {
	m.queries.WithLabelValues(string(dataset), "failed").Inc()
	m.answer.WithLabelValues(string(dataset)).Observe(elapsed.Seconds())
}
