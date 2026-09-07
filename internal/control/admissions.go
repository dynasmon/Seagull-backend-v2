package control

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Where the data plane is told what the registry decided. The control plane owns
// the record and the log carries it; nothing reads the registry to admit a
// batch.
type Admissions interface {
	Publish(ctx context.Context, record *agentv1.Admission) error
}

// The registry is written first and the log after it, so a crash between the two
// leaves an agent whose decision has not reached the gateway rather than a
// gateway acting on a decision that was never recorded. What is outstanding is
// read back from the registry and published again.
func carry(ctx context.Context, agents Agents, admissions Admissions, instruments *Metrics, record *agentv1.Admission) error {
	if err := admissions.Publish(ctx, record); err != nil {
		instruments.agentAnnounced("refused")
		return err
	}
	if err := agents.Announced(ctx, record.GetAgentId(), record.GetRevision()); err != nil {
		instruments.agentAnnounced("unrecorded")
		return err
	}
	instruments.agentAnnounced("published")
	return nil
}

func (s *Server) announce(ctx context.Context, moved *agentv1.Agent) {
	if err := carry(ctx, s.agents, s.admissions, s.metrics, agent.Admission(moved)); err != nil {
		s.logger.Warn("agent_admission_not_published",
			slog.String("agent_id", moved.GetAgentId()),
			slog.Uint64("revision", moved.GetRevision()),
			slog.String("error", err.Error()),
		)
	}
}

// Publishes what the registry has decided and the log has not been told, at
// startup and on every tick: it is what repairs a control plane that recorded a
// revocation and then could not reach the backbone. One record it cannot carry
// stops the sweep rather than being stepped over, because the records go oldest
// first and skipping one would tell a gateway a later state while an earlier one
// is still missing.
type Announcer struct {
	agents     Agents
	admissions Admissions
	metrics    *Metrics
	logger     *slog.Logger
	every      time.Duration
	batch      int
}

type AnnouncerOptions struct {
	Agents     Agents
	Admissions Admissions
	Metrics    *Metrics
	Logger     *slog.Logger
	Every      time.Duration
	Batch      int
}

func NewAnnouncer(options AnnouncerOptions) (*Announcer, error) {
	switch {
	case options.Agents == nil:
		return nil, errors.New("an announcer needs the registry whose decisions it carries")
	case options.Admissions == nil:
		return nil, errors.New("an announcer needs somewhere to carry a decision to")
	case options.Metrics == nil:
		return nil, errors.New("an announcer needs metrics")
	case options.Logger == nil:
		return nil, errors.New("an announcer needs a logger")
	case options.Every <= 0:
		return nil, errors.New("an announcer needs a positive interval")
	case options.Batch <= 0:
		return nil, errors.New("an announcer needs a positive batch ceiling")
	}
	return &Announcer{
		agents:     options.Agents,
		admissions: options.Admissions,
		metrics:    options.Metrics,
		logger:     options.Logger,
		every:      options.Every,
		batch:      options.Batch,
	}, nil
}

func (a *Announcer) Name() string { return "agent-announcer" }

func (a *Announcer) Run(ctx context.Context) error {
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

func (a *Announcer) Sweep(ctx context.Context) {
	outstanding, err := a.agents.Outstanding(ctx, a.batch)
	if err != nil {
		a.logger.Warn("agent_admissions_unreadable", slog.String("error", err.Error()))
		return
	}
	a.metrics.agentsOutstanding(len(outstanding))

	for _, record := range outstanding {
		if err := carry(ctx, a.agents, a.admissions, a.metrics, record); err != nil {
			a.logger.Warn("agent_admission_not_published",
				slog.String("agent_id", record.GetAgentId()),
				slog.Uint64("revision", record.GetRevision()),
				slog.String("error", err.Error()),
			)
			return
		}
	}
}
