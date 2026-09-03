package control

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Metrics struct {
	policy      *prometheus.GaugeVec
	roles       prometheus.Gauge
	bindings    prometheus.Gauge
	pinnedAt    prometheus.Gauge
	reloads     *prometheus.CounterVec
	authn       *prometheus.CounterVec
	authz       *prometheus.CounterVec
	sessions    prometheus.Gauge
	opened      prometheus.Counter
	revoked     *prometheus.CounterVec
	ratelimited prometheus.Counter
	published   *prometheus.CounterVec
	activated   *prometheus.CounterVec
	moved       *prometheus.CounterVec
	correlated  *prometheus.CounterVec
}

func NewMetrics(registry *metrics.Registry) *Metrics {
	instruments := &Metrics{
		policy: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "policy_info",
			Help:      "Identity of the policy the process is pinned to.",
		}, []string{"policy"}),
		roles: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "policy_roles",
			Help:      "Roles the current policy declares.",
		}),
		bindings: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "policy_bindings",
			Help:      "Subjects the current policy binds.",
		}),
		pinnedAt: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "policy_pinned_timestamp_seconds",
			Help:      "When the process last changed the policy it is pinned to.",
		}),
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "policy_reloads_total",
			Help:      "Attempts to read the policy source again, by what came of them.",
		}, []string{"outcome"}),
		authn: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "authentications_total",
			Help:      "Attempts to establish who a caller is, by what came of them.",
		}, []string{"outcome"}),
		authz: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "authorizations_total",
			Help:      "Decisions about what a caller may do, by why they were decided that way.",
		}, []string{"reason", "resource", "action"}),
		sessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "sessions_live",
			Help:      "Sessions this process has minted and still honours.",
		}),
		opened: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "sessions_opened_total",
			Help:      "Sessions minted.",
		}),
		revoked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "sessions_ended_total",
			Help:      "Sessions that stopped being spendable, by what ended them.",
		}, []string{"cause"}),
		ratelimited: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "rate_limited_total",
			Help:      "Requests refused for spending more than a caller's share.",
		}),
		published: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "rulesets_published_total",
			Help:      "Attempts to publish a ruleset, by what came of them.",
		}, []string{"outcome"}),
		activated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "rulesets_activated_total",
			Help:      "Attempts to activate a published ruleset, by what came of them.",
		}, []string{"outcome"}),
		moved: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "alerts_moved_total",
			Help:      "Attempts to move an alert, by the state it reached or by refusal.",
		}, []string{"outcome"}),
		correlated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "control",
			Name:      "incidents_moved_total",
			Help:      "Attempts to move an incident, by the state it reached or by refusal.",
		}, []string{"outcome"}),
	}

	registry.MustRegister(
		instruments.policy, instruments.roles, instruments.bindings, instruments.pinnedAt,
		instruments.reloads, instruments.authn, instruments.authz,
		instruments.sessions, instruments.opened, instruments.revoked, instruments.ratelimited,
		instruments.published, instruments.activated, instruments.moved, instruments.correlated,
	)
	return instruments
}

// One series and not one per policy ever loaded: the identity is a label, and
// the previous one is cleared so a dashboard reads what is running now.
func (m *Metrics) pinned(policy *authz.Policy) {
	if m == nil || policy == nil {
		return
	}
	m.policy.Reset()
	m.policy.WithLabelValues(policy.ID().String()).Set(1)
	m.roles.Set(float64(policy.Roles()))
	m.bindings.Set(float64(policy.Bindings()))
	m.pinnedAt.Set(float64(time.Now().Unix()))
}

func (m *Metrics) reloaded(outcome string) {
	if m != nil {
		m.reloads.WithLabelValues(outcome).Inc()
	}
}

func (m *Metrics) authenticated(outcome string) {
	if m != nil {
		m.authn.WithLabelValues(outcome).Inc()
	}
}

func (m *Metrics) decided(decision authz.Decision) {
	if m == nil {
		return
	}
	m.authz.WithLabelValues(
		string(decision.Reason),
		string(decision.Permission.Resource),
		string(decision.Permission.Action),
	).Inc()
}

func (m *Metrics) sessionOpened(live int) {
	if m != nil {
		m.opened.Inc()
		m.sessions.Set(float64(live))
	}
}

func (m *Metrics) sessionsEnded(cause string, count, live int) {
	if m == nil {
		return
	}
	if count > 0 {
		m.revoked.WithLabelValues(cause).Add(float64(count))
	}
	m.sessions.Set(float64(live))
}

func (m *Metrics) limited() {
	if m != nil {
		m.ratelimited.Inc()
	}
}

func (m *Metrics) rulesetPublished(outcome string) {
	if m != nil {
		m.published.WithLabelValues(outcome).Inc()
	}
}

func (m *Metrics) rulesetActivated(outcome string) {
	if m != nil {
		m.activated.WithLabelValues(outcome).Inc()
	}
}

func (m *Metrics) alertMoved(outcome string) {
	if m != nil {
		m.moved.WithLabelValues(outcome).Inc()
	}
}

func (m *Metrics) incidentMoved(outcome string) {
	if m != nil {
		m.correlated.WithLabelValues(outcome).Inc()
	}
}
