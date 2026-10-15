package control

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const (
	UpdateRolloutsPath       = "/v1/agents/update/rollouts"
	UpdateRolloutSearch      = "/v1/agents/update/rollouts/search"
	UpdateRolloutChangesPath = "/v1/agents/update/rollouts/changes"
	UpdateRolloutPath        = "/v1/agents/update/rollouts/{tenant}/{rollout}"

	MaxRolloutBodyBytes = 1 << 20

	// How many agents one read of the status store asks about, so a rollout of
	// a whole tenant is read in pieces of the size an agent list is.
	readingChunk = 1000
)

const (
	CodeMalformedRollout    = "malformed_rollout"
	CodeRolloutUnregistered = "rollout_names_unregistered_agents"
	CodeUnknownRollout      = "unknown_rollout"
	CodeRolloutConflict     = "rollout_change_not_applicable"
)

// Where the platform keeps the rollouts operators started and how far each
// went. What a rollout asks of one agent is read with the release it is asked
// to run, through AgentUpdates.
type AgentRollouts interface {
	Start(ctx context.Context, accepted agentupdate.AcceptedRollout) (*updatev1.RolloutRecord, error)
	Change(ctx context.Context, accepted agentupdate.AcceptedChange) (*updatev1.RolloutRecord, error)
	Page(ctx context.Context, asked *updatev1.RolloutQuery, tenants []string) (*updatev1.RolloutPage, error)
	Rollout(ctx context.Context, tenant, rolloutID string, tenants []string) (*updatev1.RolloutRecord, error)
	InForce(ctx context.Context) ([]agentupdate.Held, error)
	Reach(ctx context.Context, held agentupdate.Held) (agentupdate.Reach, error)
	Settle(ctx context.Context, settled agentupdate.Settled) (bool, error)
	Catalog(ctx context.Context) ([]byte, error)
}

func (s *Server) startRollout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		var asked updatev1.Rollout
		if !readWithin(w, r, &asked, MaxRolloutBodyBytes) {
			return
		}
		decision := caller.Grant.DecideWithin(
			authz.Permission{Resource: authz.Agents, Action: authz.Write}, asked.GetTenantId())
		s.metrics.decided(decision)
		if !decision.Allowed() {
			Refuse(w, http.StatusForbidden, CodeForbidden,
				"rolling a release out to agents of "+asked.GetTenantId()+" needs "+decision.Permission.String()+" there")
			return
		}
		if !s.updatesConfigured(w, "rollout") || !s.rolloutsConfigured(w) {
			return
		}
		accepted, err := agentupdate.AcceptRollout(&asked, caller.Subject, s.now())
		if err == nil {
			_, err = s.rollouts.Start(r.Context(), accepted)
		}
		if err != nil {
			s.metrics.updatePublished("rollout", "refused")
			s.refuseRollout(w, err)
			return
		}
		record := accepted.Record
		s.metrics.updatePublished("rollout", "published")
		s.logger.Info("agent_rollout_started",
			slog.String("rollout_id", record.GetRolloutId()),
			slog.String("tenant_id", asked.GetTenantId()),
			slog.String("version", asked.GetVersion()),
			slog.Int("agents", len(asked.GetAgentIds())),
			slog.Int("waves", len(asked.GetWaves())),
			slog.Uint64("failures", uint64(asked.GetFailures())),
			slog.String("started_by", record.GetCreatedBy()),
		)
		respond(w, http.StatusCreated, record)
	})
}

func (s *Server) changeRollout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		var asked updatev1.RolloutChange
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}
		decision := caller.Grant.DecideWithin(
			authz.Permission{Resource: authz.Agents, Action: authz.Write}, asked.GetTenantId())
		s.metrics.decided(decision)
		if !decision.Allowed() {
			Refuse(w, http.StatusForbidden, CodeForbidden,
				"changing a rollout of "+asked.GetTenantId()+" needs "+decision.Permission.String()+" there")
			return
		}
		if !s.rolloutsConfigured(w) {
			return
		}
		accepted, err := agentupdate.AcceptChange(&asked, caller.Subject, s.now())
		var changed *updatev1.RolloutRecord
		if err == nil {
			changed, err = s.rollouts.Change(r.Context(), accepted)
		}
		if err != nil {
			s.metrics.updatePublished("rollout_change", "refused")
			s.refuseRollout(w, err)
			return
		}
		s.metrics.updatePublished("rollout_change", "published")
		s.logger.Info("agent_rollout_changed",
			slog.String("rollout_id", changed.GetRolloutId()),
			slog.String("tenant_id", accepted.TenantID),
			slog.String("action", asked.GetAction().String()),
			slog.String("state", agentupdate.StateName(changed.GetState())),
			slog.Uint64("wave", uint64(changed.GetWave())),
			slog.String("changed_by", changed.GetChangedBy()),
		)
		respond(w, http.StatusOK, changed)
	})
}

func (s *Server) searchRollouts() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		var asked updatev1.RolloutQuery
		if !readWithin(w, r, &asked, MaxBodyBytes) || !s.rolloutsConfigured(w) {
			return
		}
		page, err := s.rollouts.Page(r.Context(), &asked, caller.Grant.Tenants())
		if err != nil {
			s.refuseRollout(w, err)
			return
		}
		respond(w, http.StatusOK, page)
	})
}

func (s *Server) describeRollout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		if !s.rolloutsConfigured(w) {
			return
		}
		record, err := s.rollouts.Rollout(r.Context(), r.PathValue("tenant"), r.PathValue("rollout"), caller.Grant.Tenants())
		if err != nil {
			s.refuseRollout(w, err)
			return
		}
		respond(w, http.StatusOK, record)
	})
}

func (s *Server) rolloutsConfigured(w http.ResponseWriter) bool {
	if s.rollouts == nil {
		Refuse(w, http.StatusServiceUnavailable, CodeUpdatesUnconfigured,
			"this control plane was given nowhere to keep rollouts, so it takes none")
		return false
	}
	return true
}

func (s *Server) refuseRollout(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, agentupdate.ErrMalformed), errors.Is(err, agentupdate.ErrNoActor):
		Refuse(w, http.StatusUnprocessableEntity, CodeMalformedRollout, err.Error())
	case errors.Is(err, agentupdate.ErrUncataloged):
		Refuse(w, http.StatusUnprocessableEntity, CodeReleaseUncataloged, err.Error())
	case errors.Is(err, agentupdate.ErrUnregistered):
		Refuse(w, http.StatusUnprocessableEntity, CodeRolloutUnregistered, err.Error())
	case errors.Is(err, agentupdate.ErrRolloutUnknown):
		Refuse(w, http.StatusNotFound, CodeUnknownRollout, "no such rollout is held in a tenant the caller holds")
	case errors.Is(err, agentupdate.ErrRolloutState):
		Refuse(w, http.StatusConflict, CodeRolloutConflict, err.Error())
	case errors.Is(err, agentupdate.ErrRolloutCursor):
		Refuse(w, http.StatusBadRequest, CodeBadCursor, err.Error())
	default:
		s.unavailable(w, CodeUpdatesUnavailable, err)
	}
}

func rolloutRoutes(s *Server) []route {
	return []route{
		{http.MethodPost, UpdateRolloutsPath, "agent_rollout_start", Permits(authz.Agents, authz.Write), s.startRollout()},
		{http.MethodPost, UpdateRolloutChangesPath, "agent_rollout_change", Permits(authz.Agents, authz.Write), s.changeRollout()},
		{http.MethodPost, UpdateRolloutSearch, "agent_rollout_search", Permits(authz.Agents, authz.Read), s.searchRollouts()},
		{http.MethodGet, UpdateRolloutPath, "agent_rollout_describe", Permits(authz.Agents, authz.Read), s.describeRollout()},
	}
}

// Reads how far every rollout in force went, at start and on every tick, and
// lets each one's gate open its next wave or pause it. A store it cannot read
// costs a reading and moves nothing: a rollout is never advanced on what the
// platform did not see, and a reading taken before an operator changed a
// rollout is never written over that change. Several control planes reading at
// once are ordered by the store the same way.
type RolloutEvaluator struct {
	rollouts   AgentRollouts
	updates    AgentUpdates
	updateRoot func() (*agentupdate.Root, error)
	reports    Reports
	metrics    *Metrics
	logger     *slog.Logger
	every      time.Duration
	now        func() time.Time
}

type RolloutEvaluatorOptions struct {
	Rollouts   AgentRollouts
	Updates    AgentUpdates
	UpdateRoot func() (*agentupdate.Root, error)
	Reports    Reports
	Metrics    *Metrics
	Logger     *slog.Logger
	Every      time.Duration
	Now        func() time.Time
}

func NewRolloutEvaluator(options RolloutEvaluatorOptions) (*RolloutEvaluator, error) {
	switch {
	case options.Rollouts == nil:
		return nil, errors.New("a rollout evaluator needs the rollouts it reads")
	case options.Updates == nil || options.UpdateRoot == nil:
		return nil, errors.New("a rollout evaluator needs the update metadata the platform holds and the root it trusts")
	case options.Reports == nil:
		return nil, errors.New("a rollout evaluator needs the status agents report")
	case options.Metrics == nil:
		return nil, errors.New("a rollout evaluator needs metrics")
	case options.Logger == nil:
		return nil, errors.New("a rollout evaluator needs a logger")
	case options.Every <= 0:
		return nil, errors.New("a rollout evaluator needs a positive interval")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &RolloutEvaluator{
		rollouts:   options.Rollouts,
		updates:    options.Updates,
		updateRoot: options.UpdateRoot,
		reports:    options.Reports,
		metrics:    options.Metrics,
		logger:     options.Logger,
		every:      options.Every,
		now:        options.Now,
	}, nil
}

func (e *RolloutEvaluator) Name() string { return "rollout-evaluator" }

func (e *RolloutEvaluator) Run(ctx context.Context) error {
	ticker := time.NewTicker(e.every)
	defer ticker.Stop()

	e.Sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			e.Sweep(ctx)
		}
	}
}

func (e *RolloutEvaluator) Sweep(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, e.every)
	defer cancel()

	held, err := e.rollouts.InForce(ctx)
	if err != nil {
		e.metrics.rolloutRead("unreadable")
		e.logger.Warn("agent_rollouts_unreadable", slog.String("error", err.Error()))
		return
	}
	e.metrics.rolloutsInForce(len(held))
	if len(held) == 0 {
		return
	}
	catalog, err := e.catalog(ctx)
	if err != nil {
		e.logger.Warn("agent_rollout_catalog_unread", slog.String("error", err.Error()))
	}
	for _, one := range held {
		e.read(ctx, one, catalog)
	}
}

// The newest catalog, verified again under the newest root the platform
// trusts, which is what an agent would hold a release to. Without one, a
// rollout is still read, and only what an agent cannot take goes unforeseen.
func (e *RolloutEvaluator) catalog(ctx context.Context) (*agentupdate.Catalog, error) {
	anchor, err := e.updateRoot()
	if err != nil {
		return nil, err
	}
	recorded, err := e.updates.Roots(ctx, anchor.Version())
	if err != nil {
		return nil, err
	}
	newest, err := anchor.Walk(recorded, e.now())
	if err != nil {
		return nil, err
	}
	served, err := e.rollouts.Catalog(ctx)
	if err != nil || len(served) == 0 {
		return nil, err
	}
	var envelope updatev1.Envelope
	if err := proto.Unmarshal(served, &envelope); err != nil {
		return nil, err
	}
	return newest.Catalog(&envelope, e.now())
}

func (e *RolloutEvaluator) read(ctx context.Context, held agentupdate.Held, catalog *agentupdate.Catalog) {
	record := held.Record
	rollout := record.GetRollout()
	tenant := rollout.GetTenantId()
	reach, err := e.rollouts.Reach(ctx, held)
	if err != nil {
		e.unread(record, err)
		return
	}

	now := e.now()
	tally := agentupdate.Tally{Progress: &updatev1.RolloutProgress{EvaluatedAt: timestamppb.New(now.UTC()), Agents: uint32(len(reach.Agents))}}
	var reached []string
	for _, id := range reach.Agents {
		if !agentupdate.Reaches(record.GetRolloutId(), rollout, record.GetWave(), id) {
			continue
		}
		tally.Progress.Reached++
		if reach.Pinned[id] {
			tally.Progress.Pinned++
			continue
		}
		reached = append(reached, id)
	}

	reports := make(map[string]*agentv1.Status, len(reached))
	for chunk := range slices.Chunk(reached, readingChunk) {
		newest, err := e.reports.Newest(ctx, chunk, []string{tenant})
		if err != nil {
			e.unread(record, err)
			return
		}
		for id, report := range newest {
			reports[id] = statusOf(report)
		}
	}

	for _, id := range reached {
		tally.Count(id, agentupdate.Judge(reports[id], rollout.GetVersion(), catalog), reach.Acknowledged[id])
	}

	next := proto.CloneOf(record)
	next.Progress = tally.Progress
	step, reason := agentupdate.Gate(next, tally.Progress, now)
	switch step {
	case agentupdate.Pause:
		next = agentupdate.Paused(next, reason, now)
	case agentupdate.Open:
		next = agentupdate.Opened(next, reason, now)
	}
	written, err := e.rollouts.Settle(ctx, agentupdate.Settled{Held: held, Record: next, Moved: step != agentupdate.Hold, Failing: tally.Failing})
	switch {
	case err != nil:
		e.unread(record, err)
		return
	case !written:
		e.metrics.rolloutRead("overtaken")
		return
	}
	e.metrics.rolloutRead("read")

	attributes := []any{
		slog.String("rollout_id", record.GetRolloutId()),
		slog.String("tenant_id", tenant),
		slog.String("version", rollout.GetVersion()),
		slog.Uint64("wave", uint64(next.GetWave())),
		slog.Uint64("reached", uint64(tally.Progress.GetReached())),
		slog.Uint64("running", uint64(tally.Progress.GetRunning())),
		slog.Uint64("failed", uint64(tally.Progress.GetFailed())),
		slog.String("reason", reason),
	}
	switch step {
	case agentupdate.Pause:
		e.metrics.rolloutGated("paused")
		e.logger.Warn("agent_rollout_paused", attributes...)
	case agentupdate.Open:
		e.metrics.rolloutGated("opened")
		e.logger.Info("agent_rollout_wave_opened", attributes...)
	}
}

func (e *RolloutEvaluator) unread(record *updatev1.RolloutRecord, err error) {
	e.metrics.rolloutRead("unreadable")
	e.logger.Warn("agent_rollout_unread",
		slog.String("rollout_id", record.GetRolloutId()),
		slog.String("tenant_id", record.GetRollout().GetTenantId()),
		slog.String("error", err.Error()),
	)
}

func statusOf(report agentstatus.Report) *agentv1.Status { return report.Status }
