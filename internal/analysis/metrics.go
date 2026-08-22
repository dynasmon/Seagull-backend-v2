package analysis

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type Metrics struct {
	events   *prometheus.CounterVec
	refusals *prometheus.CounterVec
	byRoute  *prometheus.CounterVec
	byClass  *prometheus.CounterVec
	batch    prometheus.Histogram
	delay    prometheus.Histogram
}

// Created once per process and handed to the engine, as the writer does it.
func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "analysis",
			Name:      "events_total",
			Help:      "Records by what the engine could do with them.",
		}, []string{"outcome"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "analysis",
			Name:      "refusals_total",
			Help:      "Records the engine could not turn into an event, by why.",
		}, []string{"reason"}),
		byRoute: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "analysis",
			Name:      "routed_total",
			Help:      "Events by the route their class sends them down.",
		}, []string{"route"}),
		byClass: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "analysis",
			Name:      "unrouted_total",
			Help:      "Events this build has no route for, by the class they carry.",
		}, []string{"class"}),
		batch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "analysis",
			Name:      "batch_events",
			Help:      "Records carried by a batch handed to the engine.",
			Buckets:   []float64{1, 10, 100, 500, 1000, 5000, 10000},
		}),
		delay: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "analysis",
			Name:      "event_delay_seconds",
			Help:      "Distance between the platform accepting an event and the engine analysing it.",
			Buckets:   []float64{0.05, 0.25, 1, 5, 30, 300, 3600},
		}),
	}
	registry.MustRegister(
		instruments.events,
		instruments.refusals,
		instruments.byRoute,
		instruments.byClass,
		instruments.batch,
		instruments.delay,
	)
	return instruments
}

func (m *Metrics) observeBatch(records int) { m.batch.Observe(float64(records)) }

func (m *Metrics) analysed(events int) {
	if events > 0 {
		m.events.WithLabelValues("analysed").Add(float64(events))
	}
}

// What the engine worked on, by kind. The outcome counter above says how many
// events it got through; this says what they were, which is the number that
// decides where the next stage is worth building.
func (m *Metrics) routed(route Route) { m.byRoute.WithLabelValues(string(route)).Inc() }

// Not a refusal: the record may be well formed and simply carry a class this
// build has no route for, which an operator answers by deploying.
func (m *Metrics) unroutable(class string) {
	m.events.WithLabelValues("unrouted").Inc()
	m.byClass.WithLabelValues(class).Inc()
}

// Offset lag says how many records are waiting; this says how long an event has
// been waiting, which is the number an operator is actually asked about.
func (m *Metrics) observeDelay(reached time.Time, record *eventv1.Event) {
	accepted := record.GetReception().GetIngestTime()
	if accepted == nil {
		return
	}
	m.delay.Observe(reached.Sub(accepted.AsTime()).Seconds())
}

func (m *Metrics) refused(reason string) {
	m.events.WithLabelValues("refused").Inc()
	m.refusals.WithLabelValues(reason).Inc()
}
