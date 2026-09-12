package ingest

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// Counted apart from telemetry rather than under a label beside it, because the
// two streams are only alike until the numbers are read: a batch here carries
// records and each record carries items, and how many of an estate's items are
// packages is the measurement that decides what the projection has to hold.
type InventoryMetrics struct {
	batches     *prometheus.CounterVec
	records     *prometheus.CounterVec
	items       *prometheus.CounterVec
	rejections  *prometheus.CounterVec
	batchSize   prometheus.Histogram
	recordItems prometheus.Histogram
	publish     prometheus.Histogram
	lag         prometheus.Histogram
}

func NewInventoryMetrics(registry *metrics.Registry) *InventoryMetrics {
	instruments := &InventoryMetrics{
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inventory_batches_total",
			Help:      "Inventory batches by admission outcome.",
		}, []string{"outcome"}),
		records: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inventory_records_total",
			Help:      "Inventory records by admission outcome.",
		}, []string{"outcome"}),
		items: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inventory_items_total",
			Help:      "Admitted inventory items by the kind of thing they are.",
		}, []string{"kind"}),
		rejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inventory_rejections_total",
			Help:      "Rejected inventory batches by reason.",
		}, []string{"reason"}),
		batchSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inventory_batch_records",
			Help:      "Records carried by an admitted inventory batch.",
			Buckets:   []float64{1, 2, 4, 8, 16, 32, 64},
		}),
		recordItems: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inventory_record_items",
			Help:      "Items carried by an admitted inventory record.",
			Buckets:   []float64{1, 10, 100, 500, 1000, 5000, 10000},
		}),
		publish: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inventory_publish_duration_seconds",
			Help:      "Time spent making an inventory batch durable in the backbone.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
		lag: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inventory_lag_seconds",
			Help:      "Distance between the time a collector looked and the time the platform accepted what it saw.",
			Buckets:   []float64{1, 5, 30, 120, 600, 3600, 86400},
		}),
	}
	registry.MustRegister(
		instruments.batches,
		instruments.records,
		instruments.items,
		instruments.rejections,
		instruments.batchSize,
		instruments.recordItems,
		instruments.publish,
		instruments.lag,
	)
	return instruments
}

func (m *InventoryMetrics) batchAccepted(records int, elapsed time.Duration) {
	m.batches.WithLabelValues("accepted").Inc()
	m.records.WithLabelValues("accepted").Add(float64(records))
	m.batchSize.Observe(float64(records))
	m.publish.Observe(elapsed.Seconds())
}

func (m *InventoryMetrics) batchRejected(reason string) {
	m.batches.WithLabelValues("rejected").Inc()
	m.rejections.WithLabelValues(reason).Inc()
}

func (m *InventoryMetrics) batchUnavailable(records int) {
	m.batches.WithLabelValues("unavailable").Inc()
	m.records.WithLabelValues("unavailable").Add(float64(records))
}

func (m *InventoryMetrics) observe(received time.Time, record *inventoryv1.Record) {
	m.items.WithLabelValues(inventory.KindName(record.GetKind())).Add(float64(len(record.GetItems())))
	m.recordItems.Observe(float64(len(record.GetItems())))
	if collected := record.GetCollectedAt(); collected != nil {
		m.lag.Observe(received.Sub(collected.AsTime()).Seconds())
	}
}
