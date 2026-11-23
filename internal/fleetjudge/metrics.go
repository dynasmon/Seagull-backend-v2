package fleetjudge

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

type Metrics struct {
	agents      prometheus.Gauge
	listening   prometheus.Gauge
	serving     prometheus.Gauge
	behind      prometheus.Gauge
	open        *prometheus.GaugeVec
	unpublished prometheus.Gauge
	decisions   *prometheus.CounterVec
	refused     *prometheus.CounterVec
	overflowed  prometheus.Counter
	unopened    *prometheus.CounterVec
	refusals    *prometheus.CounterVec
}

func NewMetrics(registry *metrics.Registry) *Metrics {
	gauge := func(name, help string) prometheus.Gauge {
		return prometheus.NewGauge(prometheus.GaugeOpts{Namespace: metrics.Namespace, Subsystem: "fleetjudge", Name: name, Help: help})
	}
	instruments := &Metrics{
		agents:      gauge("agents", "Agents the judge holds the newest report of."),
		listening:   gauge("listening", "Whether the judge confirmed it reads the end of the status log while a gateway admits, which is when it judges silence."),
		serving:     gauge("serving_gateways", "Gateways whose newest beacon said they admit, within three of their intervals."),
		behind:      gauge("status_behind_records", "Records of the status log the judge had not read when it last asked."),
		unpublished: gauge("unpublished_decisions", "Decisions the backbone has not taken yet, published again at every sweep."),
		open: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace, Subsystem: "fleetjudge", Name: "open_findings",
			Help: "Findings this judge holds open, by kind.",
		}, []string{"kind"}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace, Subsystem: "fleetjudge", Name: "decisions_total",
			Help: "Decisions the backbone took, by the kind of finding and where it stood.",
		}, []string{"kind", "state"}),
		refused: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace, Subsystem: "fleetjudge", Name: "refused_records_total",
			Help: "Records the judge could not read, by the log they came from.",
		}, []string{"log"}),
		overflowed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.Namespace, Subsystem: "fleetjudge", Name: "agents_refused_total",
			Help: "Reports of agents beyond the judge's ceiling, which stops it judging silence until it is raised.",
		}),
		unopened: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace, Subsystem: "fleetjudge", Name: "findings_not_opened_total",
			Help: "Episodes not opened because their agent already held four open findings of their kind, all answered at once by the operator answering the agent.",
		}, []string{"kind"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace, Subsystem: "fleetjudge", Name: "refusals_total",
			Help: "Refusals of a replaced certificate the gateways published, by whether they were evidence of the certificate in force or of an episode already over.",
		}, []string{"outcome"}),
	}
	for _, kind := range agentfinding.Kinds() {
		instruments.open.WithLabelValues(agentfinding.KindName(kind))
	}
	for _, kind := range []agentv1.Finding_Kind{agentv1.Finding_KIND_COPIED_INSTALLATION, agentv1.Finding_KIND_SHARED_IDENTITY} {
		instruments.unopened.WithLabelValues(agentfinding.KindName(kind))
	}
	for _, log := range []string{"status", "admissions", "beacons", "findings", "refusals"} {
		instruments.refused.WithLabelValues(log)
	}
	for _, outcome := range []string{"counted", "outdated"} {
		instruments.refusals.WithLabelValues(outcome)
	}
	registry.MustRegister(instruments.agents, instruments.listening, instruments.serving, instruments.behind,
		instruments.open, instruments.unpublished, instruments.decisions, instruments.refused, instruments.overflowed,
		instruments.unopened, instruments.refusals)
	return instruments
}

func (m *Metrics) decided(published []*agentv1.Finding) {
	for _, one := range published {
		m.decisions.WithLabelValues(agentfinding.KindName(one.GetKind()), agentfinding.StateName(one.GetState())).Inc()
	}
}

func flag(on bool) float64 {
	if on {
		return 1
	}
	return 0
}
