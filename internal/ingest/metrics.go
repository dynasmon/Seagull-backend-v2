package ingest

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type Metrics struct {
	batches    *prometheus.CounterVec
	events     *prometheus.CounterVec
	rejections *prometheus.CounterVec
	batchSize  prometheus.Histogram
	publish    prometheus.Histogram
	lag        prometheus.Histogram
}

func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "batches_total",
			Help:      "Event batches by admission outcome.",
		}, []string{"outcome"}),
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "events_total",
			Help:      "Events by admission outcome.",
		}, []string{"outcome"}),
		rejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "rejections_total",
			Help:      "Rejected batches by reason.",
		}, []string{"reason"}),
		batchSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "batch_events",
			Help:      "Events carried by an admitted batch.",
			Buckets:   []float64{1, 10, 100, 500, 1000, 5000, 10000},
		}),
		publish: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "publish_duration_seconds",
			Help:      "Time spent making a batch durable in the backbone.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.5, 2, 10},
		}),
		lag: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "event_lag_seconds",
			Help:      "Distance between the time an event happened and the time the platform accepted it.",
			Buckets:   []float64{1, 5, 30, 120, 600, 3600, 86400},
		}),
	}
	registry.MustRegister(
		instruments.batches,
		instruments.events,
		instruments.rejections,
		instruments.batchSize,
		instruments.publish,
		instruments.lag,
	)
	return instruments
}

func (m *Metrics) batchAccepted(events int, elapsed time.Duration) {
	m.batches.WithLabelValues("accepted").Inc()
	m.events.WithLabelValues("accepted").Add(float64(events))
	m.batchSize.Observe(float64(events))
	m.publish.Observe(elapsed.Seconds())
}

func (m *Metrics) batchRejected(reason string) {
	m.batches.WithLabelValues("rejected").Inc()
	m.rejections.WithLabelValues(reason).Inc()
}

func (m *Metrics) batchUnavailable(events int) {
	m.batches.WithLabelValues("unavailable").Inc()
	m.events.WithLabelValues("unavailable").Add(float64(events))
}

// Registered by the executable, because only it knows which gateway the
// ceiling was chosen for.
func ObserveCapacity(registry *metrics.Registry, capacity *Capacity) {
	bytes, requests := capacity.Bounds()
	registry.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inflight_bytes",
			Help:      "Request bytes the gateway has reserved and not yet released.",
		}, func() float64 { held, _ := capacity.Held(); return float64(held) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inflight_requests",
			Help:      "Requests the gateway is holding at once.",
		}, func() float64 { _, inflight := capacity.Held(); return float64(inflight) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inflight_byte_ceiling",
			Help:      "Request bytes the gateway holds at once before it refuses work.",
		}, func() float64 { return float64(bytes) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ingest",
			Name:      "inflight_request_ceiling",
			Help:      "Requests the gateway holds at once before it refuses work.",
		}, func() float64 { return float64(requests) }),
	)
}

func (m *Metrics) observeLag(received time.Time, record *eventv1.Event) {
	eventTime := record.GetTime().GetEventTime()
	if eventTime == nil {
		return
	}
	m.lag.Observe(received.Sub(eventTime.AsTime()).Seconds())
}
