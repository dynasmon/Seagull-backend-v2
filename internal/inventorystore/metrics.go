package inventorystore

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	records  *prometheus.CounterVec
	items    *prometheus.CounterVec
	scans    prometheus.Counter
	batches  *prometheus.CounterVec
	refusals *prometheus.CounterVec
	batch    prometheus.Histogram
	write    prometheus.Histogram
}

// Created once per process and handed to the projector, as the writers do it.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		records: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "inventorystore",
			Name:      "records_total",
			Help:      "Records by what the inventory projector did with them.",
		}, []string{"outcome"}),
		items: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "inventorystore",
			Name:      "items_total",
			Help:      "Items folded into the current state of an asset, by the kind of thing they are.",
		}, []string{"kind"}),
		scans: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "inventorystore",
			Name:      "scans_total",
			Help:      "Full enumerations that moved the line absence is measured against.",
		}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "inventorystore",
			Name:      "batches_total",
			Help:      "Batches of records by whether they became durable or had to be retried.",
		}, []string{"outcome"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "inventorystore",
			Name:      "refusals_total",
			Help:      "Records that were not inventory this build could store, by why.",
		}, []string{"reason"}),
		batch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "inventorystore",
			Name:      "batch_records",
			Help:      "Records carried by a batch handed to the inventory projector.",
			Buckets:   []float64{1, 2, 4, 8, 16, 32, 64, 128},
		}),
		write: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "inventorystore",
			Name:      "write_duration_seconds",
			Help:      "Time spent making a batch of inventory durable in the store.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
	}
	registry.MustRegister(
		instruments.records,
		instruments.items,
		instruments.scans,
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
func (m *Metrics) stored(records int, rows []Row, scans []Scan, elapsed time.Duration) {
	m.records.WithLabelValues("stored").Add(float64(records))
	m.scans.Add(float64(len(scans)))
	for _, row := range rows {
		m.items.WithLabelValues(row.Kind).Inc()
	}
	m.write.Observe(elapsed.Seconds())
}

func (m *Metrics) quarantined(refused []Refused) {
	m.records.WithLabelValues("quarantined").Add(float64(len(refused)))
	for _, entry := range refused {
		m.refusals.WithLabelValues(entry.Reason).Inc()
	}
}
