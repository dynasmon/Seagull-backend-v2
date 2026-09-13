package advisorystore

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	records  *prometheus.CounterVec
	rows     *prometheus.CounterVec
	batches  *prometheus.CounterVec
	refusals *prometheus.CounterVec
	batch    prometheus.Histogram
	write    prometheus.Histogram
}

func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		records: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisorystore",
			Name:      "records_total",
			Help:      "Advisory records by what the writer did with them.",
		}, []string{"outcome"}),
		rows: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisorystore",
			Name:      "rows_total",
			Help:      "Rows written, by the table they were written to.",
		}, []string{"table"}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisorystore",
			Name:      "batches_total",
			Help:      "Batches of records by whether they became durable or had to be retried.",
		}, []string{"outcome"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisorystore",
			Name:      "refusals_total",
			Help:      "Records that were not advisories this build could store, by why.",
		}, []string{"reason"}),
		batch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisorystore",
			Name:      "batch_records",
			Help:      "Records carried by a batch handed to the advisory writer.",
			Buckets:   []float64{1, 4, 16, 64, 256, 1024},
		}),
		write: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisorystore",
			Name:      "write_duration_seconds",
			Help:      "Time spent making a batch of advisories durable in the store.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
	}
	registry.MustRegister(
		instruments.records,
		instruments.rows,
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

// A retried batch is written again, so these count successful writes and not
// distinct records; `batches_total{outcome="retried"}` explains the difference.
func (m *Metrics) stored(records int, projected Projection, elapsed time.Duration) {
	m.records.WithLabelValues("stored").Add(float64(records))
	m.rows.WithLabelValues("advisories").Add(float64(len(projected.Advisories)))
	m.rows.WithLabelValues("affected").Add(float64(len(projected.Affected)))
	m.rows.WithLabelValues("feed_syncs").Add(float64(len(projected.Syncs)))
	m.write.Observe(elapsed.Seconds())
}

func (m *Metrics) quarantined(refused []Refused) {
	m.records.WithLabelValues("quarantined").Add(float64(len(refused)))
	for _, entry := range refused {
		m.refusals.WithLabelValues(entry.Reason).Inc()
	}
}
