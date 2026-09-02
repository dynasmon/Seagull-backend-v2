package analysis

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type Metrics struct {
	events   *prometheus.CounterVec
	refusals *prometheus.CounterVec
	byRoute  *prometheus.CounterVec
	byClass  *prometheus.CounterVec
	rewrites *prometheus.CounterVec
	batch    prometheus.Histogram
	delay    prometheus.Histogram

	evaluations *prometheus.CounterVec
	matches     *prometheus.CounterVec
	deciding    *prometheus.HistogramVec
	emitted     prometheus.Counter
	batches     *prometheus.CounterVec

	observations *prometheus.CounterVec
	floors       prometheus.Counter
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
		rewrites: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "analysis",
			Name:      "normalized_total",
			Help:      "Events the engine had to rewrite into canonical form, by route.",
		}, []string{"route"}),
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
		evaluations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "detection",
			Name:      "evaluations_total",
			Help:      "Rules decided against an event, by the route they are registered on.",
		}, []string{"route"}),
		matches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "detection",
			Name:      "matches_total",
			Help:      "Rules that matched an event, by route and by how much the rule says it matters.",
		}, []string{"route", "severity"}),
		deciding: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "detection",
			Name:      "seconds",
			Help:      "Time spent deciding one event against every rule on its route.",
			Buckets:   []float64{0.000005, 0.000025, 0.0001, 0.00025, 0.001, 0.005, 0.025},
		}, []string{"route"}),
		emitted: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "detection",
			Name:      "published_total",
			Help:      "Detections the backbone made durable.",
		}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "detection",
			Name:      "batches_total",
			Help:      "Batches of detections by whether the backbone took them; a retry is counted apart from the batch it belongs to.",
		}, []string{"outcome"}),
		observations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "detection",
			Name:      "state_observations_total",
			Help:      "Events a counting rule matched, by what its window did with them.",
		}, []string{"outcome"}),
		floors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "detection",
			Name:      "state_saturated_total",
			Help:      "Observations folded into a key that was already full, whose count is therefore a floor.",
		}),
	}
	registry.MustRegister(
		instruments.events,
		instruments.refusals,
		instruments.byRoute,
		instruments.byClass,
		instruments.rewrites,
		instruments.batch,
		instruments.delay,
		instruments.evaluations,
		instruments.matches,
		instruments.deciding,
		instruments.emitted,
		instruments.batches,
		instruments.observations,
		instruments.floors,
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

// Against routed_total this says what share of a deployment's telemetry arrives
// in a form the engine has to correct, which is a question about the agents
// rather than about the engine.
func (m *Metrics) normalized(route Route) { m.rewrites.WithLabelValues(string(route)).Inc() }

// Offset lag says how many records are waiting; this says how long an event has
// been waiting, which is the number an operator is actually asked about.
func (m *Metrics) observeDelay(reached time.Time, record *eventv1.Event) {
	accepted := record.GetReception().GetIngestTime()
	if accepted == nil {
		return
	}
	m.delay.Observe(reached.Sub(accepted.AsTime()).Seconds())
}

// What detection cost, which is the number that decides whether a ruleset can
// grow: evaluations against events says how much work a rule adds, and the
// histogram says what one event's worth of it takes.
func (m *Metrics) evaluated(route Route, rules int, took time.Duration) {
	if rules > 0 {
		m.evaluations.WithLabelValues(string(route)).Add(float64(rules))
	}
	m.deciding.WithLabelValues(string(route)).Observe(took.Seconds())
}

// Which rule fired is not a label here: a ruleset is unbounded from this
// process's point of view, and what fired belongs in the detection record where
// it can be queried instead of held open as a series.
func (m *Metrics) detected(route Route, severity detection.Severity) {
	m.matches.WithLabelValues(string(route), string(severity)).Inc()
}

// Against matches_total this is the number that says whether what the engine
// decided actually left the process: a gap between the two is findings nobody
// downstream has been told about.
func (m *Metrics) published(detections int) {
	m.emitted.Add(float64(detections))
	m.batches.WithLabelValues("published").Inc()
}

// Counted apart from the batch it belongs to, so the two together say how hard
// the engine had to work to make one batch durable rather than how many batches
// there were.
func (m *Metrics) publishRetried() { m.batches.WithLabelValues("retried").Inc() }

func (m *Metrics) refused(reason string) {
	m.events.WithLabelValues("refused").Inc()
	m.refusals.WithLabelValues(reason).Inc()
}

// What a counting rule's window did with an event it matched. Counted and
// reached say the rule is working; the three refusals say the store would not
// take the observation, which is a rule that cannot fire and an operator who
// would otherwise never know.
func (m *Metrics) observed(outcome string) { m.observations.WithLabelValues(outcome).Inc() }

func (m *Metrics) saturated() { m.floors.Inc() }
