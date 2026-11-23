package control

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// The registry keeps every episode of a replaced certificate presented again,
// and a finding is decided again every day it stays open, as the store's
// retention assumes of every decider (ADR 56).
const findingsAgain = 24 * time.Hour

type Replacements interface {
	Unpublished(ctx context.Context, limit int) ([]agentfinding.Replaced, error)
	Published(ctx context.Context, used agentfinding.Replaced) error
	DecideAgain(ctx context.Context, before, now time.Time) error
}

type FindingDecisions interface {
	Publish(ctx context.Context, decided []*agentv1.Finding) error
}

func renewalUse() *agentv1.Finding_Use {
	return &agentv1.Finding_Use{Listener: agentv1.Finding_Use_LISTENER_CONTROL, Route: http.MethodPost + " " + RenewalPath}
}

// Hands the findings log what the registry decided about replaced certificates
// and the log was not told, oldest first, as the announcer hands the gateways
// the admissions: a decision the log did not take stays in the registry and is
// handed over again at the next sweep.
type FindingAnnouncer struct {
	replacements Replacements
	decisions    FindingDecisions
	metrics      *Metrics
	logger       *slog.Logger
	every        time.Duration
	batch        int
	now          func() time.Time
}

type FindingAnnouncerOptions struct {
	Replacements Replacements
	Decisions    FindingDecisions
	Metrics      *Metrics
	Logger       *slog.Logger
	Every        time.Duration
	Batch        int
	Now          func() time.Time
}

func NewFindingAnnouncer(options FindingAnnouncerOptions) (*FindingAnnouncer, error) {
	switch {
	case options.Replacements == nil:
		return nil, errors.New("a finding announcer needs the registry whose decisions it carries")
	case options.Decisions == nil:
		return nil, errors.New("a finding announcer needs somewhere to carry a decision to")
	case options.Metrics == nil || options.Logger == nil:
		return nil, errors.New("a finding announcer reports what it does, and was given nowhere to")
	case options.Every <= 0 || options.Batch <= 0:
		return nil, errors.New("a finding announcer needs a positive interval and batch ceiling")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &FindingAnnouncer{
		replacements: options.Replacements, decisions: options.Decisions, metrics: options.Metrics, logger: options.Logger,
		every: options.Every, batch: options.Batch, now: options.Now,
	}, nil
}

func (a *FindingAnnouncer) Name() string { return "agent-finding-announcer" }

func (a *FindingAnnouncer) Run(ctx context.Context) error {
	ticker := time.NewTicker(a.every)
	defer ticker.Stop()

	a.Sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			a.Sweep(ctx)
		}
	}
}

func (a *FindingAnnouncer) Sweep(ctx context.Context) {
	now := a.now()
	if err := a.replacements.DecideAgain(ctx, now.Add(-findingsAgain), now); err != nil {
		a.logger.Warn("agent_findings_not_decided_again", slog.String("error", err.Error()))
	}
	waiting, err := a.replacements.Unpublished(ctx, a.batch)
	if err != nil {
		a.logger.Warn("agent_findings_unreadable", slog.String("error", err.Error()))
		return
	}
	a.metrics.findingsOutstanding(len(waiting))
	if len(waiting) == 0 {
		return
	}
	decided := make([]*agentv1.Finding, 0, len(waiting))
	for _, used := range waiting {
		decided = append(decided, used.Finding(renewalUse()))
	}
	if err := a.decisions.Publish(ctx, decided); err != nil {
		a.metrics.findingsCarried("refused", len(decided))
		a.logger.Warn("agent_findings_not_published", slog.Int("decisions", len(decided)), slog.String("error", err.Error()))
		return
	}
	for index, used := range waiting {
		if err := a.replacements.Published(ctx, used); err != nil {
			a.metrics.findingsCarried("unrecorded", len(waiting)-index)
			a.logger.Warn("agent_findings_unrecorded", slog.String("agent_id", used.AgentID), slog.String("error", err.Error()))
			return
		}
		a.logger.Info("agent_finding_decided",
			slog.String("agent_id", used.AgentID),
			slog.String("kind", agentfinding.KindName(agentv1.Finding_KIND_REPLACED_CERTIFICATE)),
			slog.String("state", agentfinding.StateName(decided[index].GetState())),
			slog.String("finding_id", decided[index].GetFindingId()),
		)
	}
	a.metrics.findingsCarried("published", len(waiting))
	a.metrics.findingsOutstanding(0)
}
