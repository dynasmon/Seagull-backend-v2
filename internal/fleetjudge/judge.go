package fleetjudge

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/listening"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

type Options struct {
	Status     StatusLog
	Admissions Log
	Beacons    Log
	Findings   Log
	Decisions  Decisions
	Metrics    *Metrics
	Logger     *slog.Logger
	Every      time.Duration
	StaleAfter time.Duration
	MaxAgents  int
	Again      time.Duration
	Now        func() time.Time
}

type admission struct {
	tenant  string
	admits  bool
	changed time.Time
}

type held struct {
	newest   *agentv1.Heard
	silence  *agentv1.Finding
	places   []*place
	episodes []*episode
}

type Judge struct {
	status     StatusLog
	admissions Log
	beacons    Log
	findings   Log
	decisions  Decisions
	metrics    *Metrics
	logger     *slog.Logger
	every      time.Duration
	staleAfter time.Duration
	maxAgents  int
	again      time.Duration
	now        func() time.Time

	mu        sync.Mutex
	agents    map[string]*held
	admitted  map[string]admission
	recalled  map[string]*agentv1.Finding
	gateways  *listening.Gateways
	stretch   listening.Stretch
	confirmed time.Time
	pending   map[string]*agentv1.Finding
	overflow  bool
	heard     bool
}

func New(options Options) (*Judge, error) {
	switch {
	case options.Status == nil || options.Admissions == nil || options.Beacons == nil || options.Findings == nil:
		return nil, errors.New("a fleet judge reads the status, the admissions, the beacons and its own findings, and was not given all four")
	case options.Decisions == nil:
		return nil, errors.New("a fleet judge needs somewhere to publish what it decides")
	case options.Metrics == nil || options.Logger == nil:
		return nil, errors.New("a fleet judge reports what it does, and was given nowhere to")
	case options.Every <= 0 || options.StaleAfter < 2*options.Every:
		return nil, errors.New("a fleet judge confirms what it reads at a positive interval, and is unconfirmed only after missing two")
	case options.MaxAgents <= 0:
		return nil, errors.New("a fleet judge holds a bounded number of agents")
	case options.Again < options.Every:
		return nil, errors.New("a fleet judge decides an open finding again no more often than it sweeps")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Judge{
		status: options.Status, admissions: options.Admissions, beacons: options.Beacons, findings: options.Findings,
		decisions: options.Decisions, metrics: options.Metrics, logger: options.Logger,
		every: options.Every, staleAfter: options.StaleAfter, maxAgents: options.MaxAgents, again: options.Again, now: options.Now,
		agents: map[string]*held{}, admitted: map[string]admission{}, recalled: map[string]*agentv1.Finding{},
		gateways: listening.NewGateways(), pending: map[string]*agentv1.Finding{},
	}, nil
}

func (j *Judge) Name() string { return "fleet-judge" }

// Everything it judges from is read whole before it judges anything. A beacon
// read back says nothing about now, so only one heard after the replay counts,
// and a silence read back from its own decisions is reconciled with the reports
// before any sweep can decide it again.
func (j *Judge) Run(ctx context.Context) error {
	for _, replayed := range []struct {
		name    string
		log     Log
		deliver Deliver
	}{
		{"admissions", j.admissions, j.admit},
		{"beacons", j.beacons, func(context.Context, []Record) error { return nil }},
		{"findings", j.findings, j.recall},
		{"status", j.status, j.replayed},
	} {
		if replayed.name == "status" {
			j.restore()
		}
		if err := replayed.log.Replay(ctx, replayed.deliver); err != nil {
			return fmt.Errorf("read the %s log whole: %w", replayed.name, err)
		}
	}
	j.reconcile()

	following, stop := context.WithCancel(ctx)
	defer stop()
	failed := make(chan error, 3)
	var group sync.WaitGroup
	for name, followed := range map[string]struct {
		log     Log
		deliver Deliver
	}{
		"admissions": {j.admissions, j.admit},
		"beacons":    {j.beacons, j.beacon},
		"status":     {j.status, j.hear},
	} {
		group.Go(func() {
			if err := followed.log.Follow(following, followed.deliver); err != nil && following.Err() == nil {
				failed <- fmt.Errorf("follow the %s log: %w", name, err)
			}
		})
	}

	ticker := time.NewTicker(j.every)
	defer ticker.Stop()
	var err error
	for err == nil && ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case err = <-failed:
		case <-ticker.C:
			j.Sweep(ctx)
		}
	}
	stop()
	group.Wait()
	j.publish(context.WithoutCancel(ctx))
	return err
}

// Sweep confirms whether the platform is listening, decides every silence that
// is due and every open finding due to be decided again, and publishes.
func (j *Judge) Sweep(ctx context.Context) {
	checking, cancel := context.WithTimeout(ctx, j.every)
	behind, _, err := j.status.Behind(checking)
	cancel()
	now := j.now()

	j.mu.Lock()
	if err == nil && behind == 0 {
		j.confirmed = now
	}
	current := !j.confirmed.IsZero() && now.Sub(j.confirmed) <= j.staleAfter
	serving := j.gateways.Serving(now)
	listens := current && serving > 0 && !j.overflow
	j.stretch.Mark(now, listens)
	j.observe(listens, current, serving, behind, err)

	for agentID, one := range j.agents {
		j.settle(one, now)
		if one.silence != nil {
			if now.Sub(one.silence.GetDecidedAt().AsTime()) >= j.again {
				one.silence = agentfinding.Again(one.silence, now)
				j.decide(one.silence)
			}
			continue
		}
		known, admitted := j.admitted[agentID]
		if !admitted || !known.admits || one.newest == nil || now.Before(agentfinding.SilentFrom(one.newest)) ||
			!j.stretch.Lasted(now, agentfinding.Threshold(one.newest)) {
			continue
		}
		one.silence = agentfinding.Silence(known.tenant, agentID, one.newest, now)
		j.decide(one.silence)
	}
	j.mu.Unlock()

	j.publish(ctx)
}

func (j *Judge) publish(ctx context.Context) {
	j.mu.Lock()
	batch := slices.SortedFunc(maps.Values(j.pending), func(a, b *agentv1.Finding) int {
		return cmp.Or(a.GetDecidedAt().AsTime().Compare(b.GetDecidedAt().AsTime()), cmp.Compare(a.GetFindingId(), b.GetFindingId()))
	})
	clear(j.pending)
	j.mu.Unlock()
	if len(batch) == 0 {
		return
	}

	within, cancel := context.WithTimeout(ctx, j.every)
	defer cancel()
	if err := j.decisions.Publish(within, batch); err != nil {
		j.mu.Lock()
		for _, decided := range batch {
			if _, newer := j.pending[decided.GetFindingId()]; !newer {
				j.pending[decided.GetFindingId()] = decided
			}
		}
		left := len(j.pending)
		j.mu.Unlock()
		j.metrics.unpublished.Set(float64(left))
		j.logger.Warn("agent_findings_unpublished", slog.Int("decisions", left), slog.String("error", err.Error()))
		return
	}
	j.metrics.unpublished.Set(0)
	j.metrics.decided(batch)
	for _, decided := range batch {
		j.logger.Info("agent_finding_decided",
			slog.String("agent_id", decided.GetAgentId()),
			slog.String("kind", agentfinding.KindName(decided.GetKind())),
			slog.String("state", agentfinding.StateName(decided.GetState())),
			slog.String("finding_id", decided.GetFindingId()),
		)
	}
}

func (j *Judge) observe(listens, current bool, serving int, behind int64, err error) {
	j.metrics.listening.Set(flag(listens))
	j.metrics.serving.Set(float64(serving))
	j.metrics.behind.Set(float64(behind))
	j.metrics.agents.Set(float64(len(j.agents)))
	open := map[string]int{}
	for _, one := range j.agents {
		if one.silence != nil {
			open[agentfinding.KindName(one.silence.GetKind())]++
		}
		for _, found := range one.episodes {
			if found.open() {
				open[agentfinding.KindName(found.finding.GetKind())]++
			}
		}
	}
	for _, kind := range agentfinding.Kinds() {
		j.metrics.open.WithLabelValues(agentfinding.KindName(kind)).Set(float64(open[agentfinding.KindName(kind)]))
	}
	if listens == j.heard {
		return
	}
	j.heard = listens
	if listens {
		j.logger.Info("fleet_judge_listening", slog.Int("serving_gateways", serving))
		return
	}
	reason := "no_gateway_admits"
	switch {
	case j.overflow:
		reason = "over_capacity"
	case !current && err != nil:
		reason = "status_unreadable"
	case !current:
		reason = "status_behind"
	}
	j.logger.Warn("fleet_judge_not_listening", slog.String("reason", reason), slog.Int64("behind", behind))
}

func (j *Judge) admit(_ context.Context, records []Record) error {
	now := j.now()
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, record := range records {
		var decided agentv1.Admission
		if err := proto.Unmarshal(record.Value, &decided); err != nil || decided.GetAgentId() == "" || decided.GetAgentId() != string(record.Key) {
			j.metrics.refused.WithLabelValues("admissions").Inc()
			continue
		}
		state, known := agent.FromWire(decided.GetState())
		changed := now
		if decided.GetChangedAt().IsValid() {
			changed = decided.GetChangedAt().AsTime()
		}
		j.admitted[decided.GetAgentId()] = admission{tenant: decided.GetTenantId(), admits: known && state.Admits(), changed: changed}
		if one := j.agents[decided.GetAgentId()]; one != nil && !(known && state.Admits()) {
			if one.silence != nil {
				j.close(one, agentv1.Finding_CLOSURE_NOT_ADMITTED, changed, now)
			}
			j.dismiss(one, changed, now)
		}
	}
	return nil
}

func (j *Judge) beacon(_ context.Context, records []Record) error {
	now := j.now()
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, record := range records {
		var said platformv1.GatewayBeacon
		if err := proto.Unmarshal(record.Value, &said); err != nil || listening.Validate(&said) != nil {
			j.metrics.refused.WithLabelValues("beacons").Inc()
			continue
		}
		j.gateways.Heard(&said, now)
	}
	return nil
}

func (j *Judge) recall(_ context.Context, records []Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, record := range records {
		var decided agentv1.Finding
		if err := proto.Unmarshal(record.Value, &decided); err != nil || agentfinding.Validate(&decided) != nil {
			j.metrics.refused.WithLabelValues("findings").Inc()
			continue
		}
		if decided.GetKind() == agentv1.Finding_KIND_REPLACED_CERTIFICATE {
			continue
		}
		if known, held := j.recalled[decided.GetFindingId()]; held && known.GetDecidedAt().AsTime().After(decided.GetDecidedAt().AsTime()) {
			continue
		}
		j.recalled[decided.GetFindingId()] = &decided
	}
	return nil
}

func (j *Judge) replayed(ctx context.Context, records []Record) error {
	return j.read(ctx, records, false)
}

func (j *Judge) hear(ctx context.Context, records []Record) error { return j.read(ctx, records, true) }

func (j *Judge) read(_ context.Context, records []Record, live bool) error {
	now := j.now()
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, record := range records {
		var report agentv1.Status
		if err := proto.Unmarshal(record.Value, &report); err != nil || agentstatus.ValidateContract(&report) != nil ||
			!report.GetReception().GetIngestTime().IsValid() || report.GetOrigin().GetAgentId() != string(record.Key) {
			j.metrics.refused.WithLabelValues("status").Inc()
			continue
		}
		agentID := report.GetOrigin().GetAgentId()
		one, known := j.agents[agentID]
		if !known {
			if len(j.agents) >= j.maxAgents {
				j.overflow = true
				j.metrics.overflowed.Inc()
				continue
			}
			one = &held{}
			j.agents[agentID] = one
		}
		heard := agentfinding.HeardOf(&report)
		if live && one.silence != nil && !agentfinding.SameReport(heard, one.silence.GetReports()[0]) {
			j.close(one, agentv1.Finding_CLOSURE_HEARD, heard.GetIngestTime().AsTime(), now, heard)
		}
		one.newest = heard
		j.locate(one, agentID, &report, heard, live, now)
	}
	return nil
}

// A silence read back from the judge's own decisions is still open only while
// its newest report is the one it was decided from: a later one means the agent
// reported again while no judge was running, and an agent the registry stopped
// admitting is no longer anybody's silence.
func (j *Judge) reconcile() {
	now := j.now()
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, recalled := range j.recalled {
		if recalled.GetState() != agentv1.Finding_STATE_OPEN {
			continue
		}
		one := j.agents[recalled.GetAgentId()]
		if one == nil {
			one = &held{}
			j.agents[recalled.GetAgentId()] = one
		}
		known := j.admitted[recalled.GetAgentId()]
		switch {
		case !known.admits:
			j.decide(agentfinding.Closed(recalled, agentv1.Finding_CLOSURE_NOT_ADMITTED, whenever(known.changed, now), now))
		case one.newest != nil && !agentfinding.SameReport(one.newest, recalled.GetReports()[0]):
			j.decide(agentfinding.Closed(recalled, agentv1.Finding_CLOSURE_HEARD, one.newest.GetIngestTime().AsTime(), now, one.newest))
		default:
			one.silence = recalled
		}
	}
	clear(j.recalled)
}

func (j *Judge) close(one *held, closure agentv1.Finding_Closure, at, now time.Time, ending ...*agentv1.Heard) {
	j.decide(agentfinding.Closed(one.silence, closure, whenever(at, now), now, ending...))
	one.silence = nil
}

func (j *Judge) decide(decided *agentv1.Finding) { j.pending[decided.GetFindingId()] = decided }

func whenever(at, now time.Time) time.Time {
	if at.IsZero() {
		return now
	}
	return at
}
