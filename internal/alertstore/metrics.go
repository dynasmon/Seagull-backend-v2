package alertstore

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	alerts  *prometheus.CounterVec
	batches *prometheus.CounterVec
	skips   *prometheus.CounterVec
	hidden  *prometheus.CounterVec
	batch   prometheus.Histogram
	write   prometheus.Histogram
}

func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		alerts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "alertstore",
			Name:      "alerts_total",
			Help:      "Detections by what became of them: raised, folded, repeated or cooled down.",
		}, []string{"outcome"}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "alertstore",
			Name:      "batches_total",
			Help:      "Batches of detections by whether they became durable or had to be retried.",
		}, []string{"outcome"}),
		skips: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "alertstore",
			Name:      "skipped_total",
			Help:      "Records that did not become an alert, by why.",
		}, []string{"reason"}),
		hidden: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "alertstore",
			Name:      "suppressed_total",
			Help:      "Detections the estate declared it does not want as work, by rule and by the reason written down.",
		}, []string{"rule", "reason"}),
		batch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "alertstore",
			Name:      "batch_detections",
			Help:      "Records carried by a batch handed to the alert writer.",
			Buckets:   []float64{1, 10, 100, 500, 1000, 5000, 10000},
		}),
		write: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "alertstore",
			Name:      "write_duration_seconds",
			Help:      "Time spent making a batch of alerts durable in the store.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
	}
	registry.MustRegister(
		instruments.alerts,
		instruments.batches,
		instruments.skips,
		instruments.hidden,
		instruments.batch,
		instruments.write,
	)
	return instruments
}

func (m *Metrics) observeBatch(records int) { m.batch.Observe(float64(records)) }

func (m *Metrics) batchRetried() { m.batches.WithLabelValues("retried").Inc() }

// Every outcome is counted separately, so the noise a fold removed and the
// activity a cooldown held back are both readable rather than inferred: a
// suppression nobody can count is a suppression that hides something.
func (m *Metrics) batchRecorded(outcomes []alert.Outcome) {
	m.batches.WithLabelValues("stored").Inc()
	for _, outcome := range outcomes {
		m.alerts.WithLabelValues(outcome.String()).Inc()
	}
}

func (m *Metrics) suppressed(rule, reason string) {
	m.hidden.WithLabelValues(rule, reason).Inc()
}

func (m *Metrics) wrote(elapsed time.Duration) { m.write.Observe(elapsed.Seconds()) }

func (m *Metrics) skipped(reason string) { m.skips.WithLabelValues(reason).Inc() }
