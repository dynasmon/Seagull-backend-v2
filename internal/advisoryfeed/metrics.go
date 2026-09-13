package advisoryfeed

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// Every series is labelled by feed, and the feeds are the handful a deployment
// names in its configuration, never anything a feed says.
type Metrics struct {
	syncs      *prometheus.CounterVec
	advisories *prometheus.CounterVec
	checked    *prometheus.GaugeVec
	synced     *prometheus.GaugeVec
	listed     *prometheus.GaugeVec
	held       *prometheus.GaugeVec
	duration   *prometheus.HistogramVec
}

func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		syncs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisoryfeed",
			Name:      "syncs_total",
			Help:      "Attempts to follow a feed, by whether they read everything it listed.",
		}, []string{"feed", "outcome"}),
		advisories: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisoryfeed",
			Name:      "advisories_total",
			Help:      "Records a feed listed as changed, by what the importer made of them.",
		}, []string{"feed", "outcome"}),
		checked: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisoryfeed",
			Name:      "checked_timestamp_seconds",
			Help:      "When the importer last asked a feed what it lists.",
		}, []string{"feed"}),
		synced: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisoryfeed",
			Name:      "synced_timestamp_seconds",
			Help:      "When the platform last held everything a feed listed: how old its copy of the feed is.",
		}, []string{"feed"}),
		listed: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisoryfeed",
			Name:      "newest_listed_timestamp_seconds",
			Help:      "The newest change a feed itself lists: how current the feed is.",
		}, []string{"feed"}),
		held: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisoryfeed",
			Name:      "held_advisories",
			Help:      "Advisories the platform holds from a feed.",
		}, []string{"feed"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "advisoryfeed",
			Name:      "sync_duration_seconds",
			Help:      "Time one attempt to follow a feed took.",
			Buckets:   []float64{0.1, 1, 10, 60, 300, 1800, 7200},
		}, []string{"feed"}),
	}
	registry.MustRegister(
		instruments.syncs,
		instruments.advisories,
		instruments.checked,
		instruments.synced,
		instruments.listed,
		instruments.held,
		instruments.duration,
	)
	return instruments
}

func (m *Metrics) settled(feed, outcome string, count int) {
	if count > 0 {
		m.advisories.WithLabelValues(feed, outcome).Add(float64(count))
	}
}

func (m *Metrics) recalled(feed string, synced time.Time) {
	m.synced.WithLabelValues(feed).Set(float64(synced.Unix()))
}

func (m *Metrics) attempted(report *vulnerabilityv1.FeedSync, elapsed time.Duration) {
	feed := report.GetFeed()
	m.syncs.WithLabelValues(feed, outcomeName(report.GetOutcome())).Inc()
	m.checked.WithLabelValues(feed).Set(float64(report.GetCheckedAt().AsTime().Unix()))
	if synced := report.GetSyncedAt(); synced != nil {
		m.synced.WithLabelValues(feed).Set(float64(synced.AsTime().Unix()))
	}
	if newest := report.GetNewestListed(); newest != nil {
		m.listed.WithLabelValues(feed).Set(float64(newest.AsTime().Unix()))
	}
	m.held.WithLabelValues(feed).Set(float64(report.GetHeld()))
	m.duration.WithLabelValues(feed).Observe(elapsed.Seconds())
}

func outcomeName(outcome vulnerabilityv1.FeedSync_Outcome) string {
	name, declared := vulnerabilityv1.FeedSync_Outcome_name[int32(outcome)]
	if !declared {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(name, "OUTCOME_"))
}
