package control_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// Enough of a rollout store to prove the routes and the evaluator, enforcing
// what the PostgreSQL one enforces: a rollout names a version the newest
// catalog names and agents registered in its tenant, takes over from the one
// in force, and a reading is written only while the rollout stands where it
// was read.
type stubRollouts struct {
	mu        sync.Mutex
	agents    *stubAgents
	updates   *stubUpdates
	held      map[string]*storedRollout
	settling  func()
	unreached error
}

type storedRollout struct {
	record       *updatev1.RolloutRecord
	changes      int64
	failing      []string
	acknowledged map[string]bool
}

func newStubRollouts(agents *stubAgents, updates *stubUpdates) *stubRollouts {
	return &stubRollouts{agents: agents, updates: updates, held: map[string]*storedRollout{}}
}

func (s *stubRollouts) Start(_ context.Context, accepted agentupdate.AcceptedRollout) (*updatev1.RolloutRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rollout := accepted.Rollout()
	if newest := s.updates.newest(); newest == nil || !newest.Names(rollout.GetVersion()) {
		return nil, fmt.Errorf("%w: %s", agentupdate.ErrUncataloged, rollout.GetVersion())
	}
	named := slices.Clone(rollout.GetAgentIds())
	for _, wave := range rollout.GetWaves() {
		named = append(named, wave.GetAgentIds()...)
	}
	for _, id := range named {
		if registered, known := s.agents.held[id]; !known || registered.GetTenantId() != rollout.GetTenantId() {
			return nil, fmt.Errorf("%w: %s", agentupdate.ErrUnregistered, id)
		}
	}
	for _, other := range s.held {
		if other.record.GetRollout().GetTenantId() == rollout.GetTenantId() && agentupdate.InForce(other.record.GetState()) {
			other.record.State = updatev1.RolloutRecord_STATE_SUPERSEDED
			other.changes++
		}
	}
	s.held[accepted.ID()] = &storedRollout{record: proto.CloneOf(accepted.Record), acknowledged: map[string]bool{}}
	return accepted.Record, nil
}

func (s *stubRollouts) Change(_ context.Context, accepted agentupdate.AcceptedChange) (*updatev1.RolloutRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held, known := s.held[accepted.RolloutID]
	if !known || held.record.GetRollout().GetTenantId() != accepted.TenantID {
		return nil, agentupdate.ErrRolloutUnknown
	}
	changed, acknowledge, err := accepted.Apply(held.record)
	if err != nil {
		return nil, err
	}
	held.record, held.changes = changed, held.changes+1
	if acknowledge {
		for _, id := range held.failing {
			held.acknowledged[id] = true
		}
	}
	return proto.CloneOf(changed), nil
}

func (s *stubRollouts) Page(_ context.Context, _ *updatev1.RolloutQuery, tenants []string) (*updatev1.RolloutPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	page := &updatev1.RolloutPage{}
	for _, held := range s.held {
		if slices.Contains(tenants, held.record.GetRollout().GetTenantId()) {
			listed := proto.CloneOf(held.record)
			listed.Rollout.AgentIds = nil
			page.Rollouts = append(page.Rollouts, listed)
		}
	}
	return page, nil
}

func (s *stubRollouts) Rollout(_ context.Context, tenant, id string, tenants []string) (*updatev1.RolloutRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held, known := s.held[id]
	if !known || held.record.GetRollout().GetTenantId() != tenant || !slices.Contains(tenants, tenant) {
		return nil, agentupdate.ErrRolloutUnknown
	}
	return proto.CloneOf(held.record), nil
}

func (s *stubRollouts) InForce(context.Context) ([]agentupdate.Held, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unreached != nil {
		return nil, s.unreached
	}
	var found []agentupdate.Held
	for _, held := range s.held {
		if agentupdate.InForce(held.record.GetState()) {
			found = append(found, agentupdate.Held{
				Record: proto.CloneOf(held.record), Named: len(held.record.GetRollout().GetAgentIds()) > 0, Changes: held.changes,
			})
		}
	}
	return found, nil
}

func (s *stubRollouts) Reach(_ context.Context, held agentupdate.Held) (agentupdate.Reach, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := s.held[held.Record.GetRolloutId()]
	reach := agentupdate.Reach{Pinned: map[string]bool{}, Acknowledged: map[string]bool{}}
	for id, registered := range s.agents.held {
		state, _ := agent.FromWire(registered.GetState())
		if registered.GetTenantId() != held.Record.GetRollout().GetTenantId() || !state.Admits() ||
			(held.Named && !slices.Contains(stored.record.GetRollout().GetAgentIds(), id)) {
			continue
		}
		reach.Agents = append(reach.Agents, id)
		if s.updates.assigned[id] != "" {
			reach.Pinned[id] = true
		}
	}
	slices.Sort(reach.Agents)
	for id := range stored.acknowledged {
		reach.Acknowledged[id] = true
	}
	return reach, nil
}

func (s *stubRollouts) Settle(_ context.Context, settled agentupdate.Settled) (bool, error) {
	if s.settling != nil {
		s.settling()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	held := s.held[settled.Record.GetRolloutId()]
	if held.changes != settled.Held.Changes {
		return false, nil
	}
	ids := held.record.GetRollout().GetAgentIds()
	held.record = proto.CloneOf(settled.Record)
	held.record.Rollout.AgentIds = ids
	held.failing = slices.Clone(settled.Failing)
	if settled.Moved {
		held.changes++
	}
	return true, nil
}

func (s *stubRollouts) Catalog(context.Context) ([]byte, error) {
	s.updates.mu.Lock()
	defer s.updates.mu.Unlock()
	if newest := s.updates.newest(); newest != nil {
		return newest.Served(), nil
	}
	return nil, nil
}

func (s *stubRollouts) only(t *testing.T) *storedRollout {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var found []*storedRollout
	for _, held := range s.held {
		if agentupdate.InForce(held.record.GetState()) {
			found = append(found, held)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d rollouts are in force", len(found))
	}
	return found[0]
}

type stubReports struct {
	mu        sync.Mutex
	newest    map[string]*agentv1.Status
	asked     [][]string
	unreached error
}

func (s *stubReports) Newest(_ context.Context, agents, tenants []string) (map[string]agentstatus.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, slices.Clone(agents))
	if s.unreached != nil {
		return nil, s.unreached
	}
	found := map[string]agentstatus.Report{}
	for _, id := range agents {
		if report, known := s.newest[id]; known && slices.Contains(tenants, report.GetOrigin().GetTenantId()) {
			found[id] = agentstatus.Report{Received: now, Status: report}
		}
	}
	return found, nil
}

func (s *stubReports) say(id string, report *agentv1.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	report.Origin = &eventv1.Origin{AgentId: id, TenantId: "default"}
	s.newest[id] = report
}

// A fleet of the default tenant, registered beside web-01, with catalog 2
// naming v0.2.0 and v0.3.0 for it.
type rolloutFleet struct {
	published publishedUpdates
	rollouts  *stubRollouts
	reports   *stubReports
	handler   http.Handler
	admin     string
	clock     time.Time
}

func newRolloutFleet(t *testing.T, h *harness, more int) *rolloutFleet {
	t.Helper()
	published := publishUpdates(t, h)
	for index := range more {
		if _, err := published.held.Register(context.Background(), &agentv1.Registration{
			AgentId: fmt.Sprintf("web-%02d", index+2), TenantId: "default",
			Platform: &agentv1.Platform{Os: "linux", Architecture: "amd64"},
		}, "dev-admin", now); err != nil {
			t.Fatal(err)
		}
	}
	fleet := &rolloutFleet{
		published: published,
		rollouts:  newStubRollouts(published.held, published.store),
		reports:   &stubReports{newest: map[string]*agentv1.Status{}},
		admin:     open(t, h, "dev-admin"),
		clock:     time.Now().UTC(),
	}
	fleet.handler = rolloutListener(t, h, published, fleet.rollouts)

	newer := []byte("!<arch>\nthe package of v0.3.0")
	if recorder := upload(t, fleet.handler, "dev-admin", fleet.admin, newer); recorder.Code != http.StatusCreated {
		t.Fatalf("giving the package answered %d: %s", recorder.Code, recorder.Body)
	}
	if recorder := call(t, fleet.handler, http.MethodPost, control.UpdateCatalogsPath, "dev-admin", fleet.admin,
		&updatev1.CatalogPublication{Catalog: updateCatalog(t, 2, published.publisher,
			packageRelease("v0.2.0", published.content), packageRelease("v0.3.0", newer))}); recorder.Code != http.StatusCreated {
		t.Fatalf("publishing catalog 2 answered %d: %s", recorder.Code, recorder.Body)
	}
	return fleet
}

func rolloutListener(t *testing.T, h *harness, published publishedUpdates, rollouts *stubRollouts) http.Handler {
	t.Helper()
	signing, bundle := testAuthority(t)
	handler, err := control.NewHandler(control.ServerOptions{
		Guard: h.guard, Sessions: h.sessions, Registry: h.registry,
		Rulesets: newStubRulesets(), Alerts: newStubAlerts(), Incidents: newStubIncidents(),
		Agents: published.held, Admissions: &stubAdmissions{}, Policies: newStubPolicies(published.held),
		Updates: published.store, UpdateRoot: published.anchor, Rollouts: rollouts,
		Authority: signing, TrustBundle: bundle, CertificateLife: time.Hour,
		Metrics: h.metrics, Logger: slog.New(slog.DiscardHandler),
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-rollouts")),
	})
	if err != nil {
		t.Fatalf("build the routes: %v", err)
	}
	return handler
}

func (f *rolloutFleet) evaluator(t *testing.T) *control.RolloutEvaluator {
	t.Helper()
	evaluator, err := control.NewRolloutEvaluator(control.RolloutEvaluatorOptions{
		Rollouts: f.rollouts, Updates: f.published.store, UpdateRoot: f.published.anchor, Reports: f.reports,
		Metrics: control.NewMetrics(metrics.New("control-api-rollout-evaluator")), Logger: slog.New(slog.DiscardHandler),
		Every: time.Minute, Now: func() time.Time { return f.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return evaluator
}

func (f *rolloutFleet) start(t *testing.T, rollout *updatev1.Rollout) *updatev1.RolloutRecord {
	t.Helper()
	recorder := call(t, f.handler, http.MethodPost, control.UpdateRolloutsPath, "dev-admin", f.admin, rollout)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("starting the rollout answered %d: %s", recorder.Code, recorder.Body)
	}
	var started updatev1.RolloutRecord
	decode(t, recorder, &started)
	return &started
}

func (f *rolloutFleet) change(t *testing.T, id string, action updatev1.RolloutChange_Action) *updatev1.RolloutRecord {
	t.Helper()
	recorder := call(t, f.handler, http.MethodPost, control.UpdateRolloutChangesPath, "dev-admin", f.admin,
		&updatev1.RolloutChange{TenantId: "default", RolloutId: id, Action: action, Note: "looked at it"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s answered %d: %s", action, recorder.Code, recorder.Body)
	}
	var changed updatev1.RolloutRecord
	decode(t, recorder, &changed)
	return &changed
}

func canaryRollout(canaries ...string) *updatev1.Rollout {
	return &updatev1.Rollout{
		TenantId: "default",
		Version:  "v0.3.0",
		Waves: []*updatev1.Wave{
			{AgentIds: canaries, Soak: durationpb.New(time.Hour), Running: uint32(len(canaries))},
			{Percent: 100},
		},
		Failures: 1,
		Note:     "move default to v0.3.0",
	}
}

func running(version string) *agentv1.Status {
	return &agentv1.Status{
		Build: &agentv1.Status_Build{Version: version, Os: "linux", Architecture: "amd64"},
		Compatibility: &agentv1.Status_Compatibility{Updates: &agentv1.Status_Updates{
			Enabled: true, Format: updatev1.Format_FORMAT_DEB, StateGeneration: 1,
		}},
	}
}

func rolledBack(from, to string) *agentv1.Status {
	report := running(from)
	report.Update = &agentv1.Status_Update{
		Stage: agentv1.Status_Update_STAGE_ROLLED_BACK, Version: to, Failure: agentv1.Status_Update_FAILURE_UNHEALTHY,
	}
	return report
}

func TestAnAdministratorRollsAReleaseOutAndSteersIt(t *testing.T) {
	h := newHarness(t, nil)
	fleet := newRolloutFleet(t, h, 2)

	started := fleet.start(t, canaryRollout("web-01"))
	if started.GetState() != updatev1.RolloutRecord_STATE_ACTIVE || started.GetCreatedBy() != "dev-admin" ||
		!agentupdate.ValidRolloutID(started.GetRolloutId()) || started.GetRollout().GetVersion() != "v0.3.0" {
		t.Fatalf("started %v", started)
	}

	described := call(t, fleet.handler, http.MethodGet, "/v1/agents/update/rollouts/default/"+started.GetRolloutId(),
		"dev-analyst", open(t, h, "dev-analyst"), nil)
	if described.Code != http.StatusOK {
		t.Fatalf("describing answered %d: %s", described.Code, described.Body)
	}
	var page updatev1.RolloutPage
	decode(t, call(t, fleet.handler, http.MethodPost, control.UpdateRolloutSearch, "dev-analyst", open(t, h, "dev-analyst"),
		&updatev1.RolloutQuery{}), &page)
	if len(page.GetRollouts()) != 1 || page.GetRollouts()[0].GetRolloutId() != started.GetRolloutId() {
		t.Fatalf("the search found %v", &page)
	}

	if paused := fleet.change(t, started.GetRolloutId(), updatev1.RolloutChange_ACTION_PAUSE); paused.GetState() != updatev1.RolloutRecord_STATE_PAUSED {
		t.Fatalf("paused into %v", paused)
	}
	refusedWith(t, call(t, fleet.handler, http.MethodPost, control.UpdateRolloutChangesPath, "dev-admin", fleet.admin,
		&updatev1.RolloutChange{TenantId: "default", RolloutId: started.GetRolloutId(), Action: updatev1.RolloutChange_ACTION_ADVANCE}),
		http.StatusConflict, control.CodeRolloutConflict)
	fleet.change(t, started.GetRolloutId(), updatev1.RolloutChange_ACTION_RESUME)
	if advanced := fleet.change(t, started.GetRolloutId(), updatev1.RolloutChange_ACTION_ADVANCE); advanced.GetWave() != 1 {
		t.Fatalf("advanced into %v", advanced)
	}

	next := fleet.start(t, canaryRollout("web-02"))
	if before := fleet.rollouts.held[started.GetRolloutId()].record; before.GetState() != updatev1.RolloutRecord_STATE_SUPERSEDED {
		t.Fatalf("the rollout a new one took over from is %v", before.GetState())
	}
	if aborted := fleet.change(t, next.GetRolloutId(), updatev1.RolloutChange_ACTION_ABORT); aborted.GetState() != updatev1.RolloutRecord_STATE_ABORTED {
		t.Fatalf("aborted into %v", aborted)
	}
	refusedWith(t, call(t, fleet.handler, http.MethodPost, control.UpdateRolloutChangesPath, "dev-admin", fleet.admin,
		&updatev1.RolloutChange{TenantId: "default", RolloutId: "3f0e2a64-6f53-4b6f-9a51-2c1d2e3f4a5b", Action: updatev1.RolloutChange_ACTION_PAUSE}),
		http.StatusNotFound, control.CodeUnknownRollout)
}

func TestARolloutNamesWhatTheNewestCatalogAndTheTenantHold(t *testing.T) {
	h := newHarness(t, nil)
	fleet := newRolloutFleet(t, h, 0)

	uncataloged := canaryRollout("web-01")
	uncataloged.Version = "v0.9.0"
	refusedWith(t, call(t, fleet.handler, http.MethodPost, control.UpdateRolloutsPath, "dev-admin", fleet.admin, uncataloged),
		http.StatusUnprocessableEntity, control.CodeReleaseUncataloged)
	refusedWith(t, call(t, fleet.handler, http.MethodPost, control.UpdateRolloutsPath, "dev-admin", fleet.admin, canaryRollout("web-09")),
		http.StatusUnprocessableEntity, control.CodeRolloutUnregistered)
	malformed := canaryRollout("web-01")
	malformed.Waves[1].Percent = 50
	refusedWith(t, call(t, fleet.handler, http.MethodPost, control.UpdateRolloutsPath, "dev-admin", fleet.admin, malformed),
		http.StatusUnprocessableEntity, control.CodeMalformedRollout)
}

func TestSteeringARolloutNeedsToWriteTheAgentsOfItsTenant(t *testing.T) {
	h := newHarness(t, nil)
	fleet := newRolloutFleet(t, h, 0)
	analyst := open(t, h, "dev-analyst")

	refusedWith(t, call(t, fleet.handler, http.MethodPost, control.UpdateRolloutsPath, "dev-analyst", analyst, canaryRollout("web-01")),
		http.StatusForbidden, control.CodeForbidden)
	elsewhere := canaryRollout("web-01")
	elsewhere.TenantId = "another"
	refusedWith(t, call(t, fleet.handler, http.MethodPost, control.UpdateRolloutsPath, "dev-admin", fleet.admin, elsewhere),
		http.StatusForbidden, control.CodeForbidden)

	started := fleet.start(t, canaryRollout("web-01"))
	refusedWith(t, call(t, fleet.handler, http.MethodPost, control.UpdateRolloutChangesPath, "dev-analyst", analyst,
		&updatev1.RolloutChange{TenantId: "default", RolloutId: started.GetRolloutId(), Action: updatev1.RolloutChange_ACTION_PAUSE}),
		http.StatusForbidden, control.CodeForbidden)
	refusedWith(t, call(t, fleet.handler, http.MethodGet, "/v1/agents/update/rollouts/another/"+started.GetRolloutId(),
		"dev-admin", fleet.admin, nil), http.StatusNotFound, control.CodeUnknownRollout)
}

func TestTheCanaryRunningTheReleaseOpensTheNextWaveOnceItSoaked(t *testing.T) {
	h := newHarness(t, nil)
	fleet := newRolloutFleet(t, h, 3)
	evaluator := fleet.evaluator(t)
	fleet.start(t, canaryRollout("web-01"))

	fleet.reports.say("web-01", running("v0.3.0"))
	fleet.reports.say("web-02", running("v0.2.0"))
	fleet.clock = time.Now().UTC().Add(30 * time.Minute)
	evaluator.Sweep(context.Background())
	held := fleet.rollouts.only(t)
	if held.record.GetWave() != 0 || held.record.GetProgress().GetRunning() != 1 || held.record.GetProgress().GetReached() != 1 ||
		held.record.GetProgress().GetAgents() != 4 {
		t.Fatalf("before its soak the rollout stood at %v", held.record)
	}

	fleet.clock = time.Now().UTC().Add(61 * time.Minute)
	evaluator.Sweep(context.Background())
	held = fleet.rollouts.only(t)
	if held.record.GetWave() != 1 || held.record.GetChangedBy() != agentupdate.Platform {
		t.Fatalf("after its soak the rollout stood at %v", held.record)
	}
	evaluator.Sweep(context.Background())
	if progress := fleet.rollouts.only(t).record.GetProgress(); progress.GetReached() != 4 || progress.GetRunning() != 1 || progress.GetPending() != 3 {
		t.Fatalf("the last wave read %v", progress)
	}
}

func TestACanaryThatFailsPausesTheRolloutAndAResumeTakesItsFailureAsKnown(t *testing.T) {
	h := newHarness(t, nil)
	fleet := newRolloutFleet(t, h, 2)
	evaluator := fleet.evaluator(t)
	started := fleet.start(t, canaryRollout("web-01", "web-02"))
	evaluator.Sweep(context.Background())

	fleet.reports.say("web-01", rolledBack("v0.2.0", "v0.3.0"))
	evaluator.Sweep(context.Background())
	held := fleet.rollouts.only(t)
	if held.record.GetState() != updatev1.RolloutRecord_STATE_PAUSED || held.record.GetProgress().GetFailed() != 1 ||
		held.record.GetChangedBy() != agentupdate.Platform || held.record.GetReason() == "" {
		t.Fatalf("a failed canary left the rollout at %v", held.record)
	}

	fleet.change(t, started.GetRolloutId(), updatev1.RolloutChange_ACTION_RESUME)
	evaluator.Sweep(context.Background())
	held = fleet.rollouts.only(t)
	if held.record.GetState() != updatev1.RolloutRecord_STATE_ACTIVE || held.record.GetProgress().GetFailed() != 0 ||
		held.record.GetProgress().GetAcknowledged() != 1 || !held.acknowledged["web-01"] {
		t.Fatalf("after a resume the rollout stood at %v", held.record)
	}

	fleet.reports.say("web-02", rolledBack("v0.2.0", "v0.3.0"))
	evaluator.Sweep(context.Background())
	if held := fleet.rollouts.only(t); held.record.GetState() != updatev1.RolloutRecord_STATE_PAUSED || held.record.GetProgress().GetFailed() != 1 {
		t.Fatalf("a failure after the resume left the rollout at %v", held.record)
	}
}

func TestAFailureReportedBeforeTheRolloutStartedPausesItLikeAnyOther(t *testing.T) {
	h := newHarness(t, nil)
	fleet := newRolloutFleet(t, h, 1)
	evaluator := fleet.evaluator(t)
	fleet.reports.say("web-01", rolledBack("v0.2.0", "v0.3.0"))
	fleet.start(t, canaryRollout("web-01", "web-02"))

	evaluator.Sweep(context.Background())
	if held := fleet.rollouts.only(t); held.record.GetState() != updatev1.RolloutRecord_STATE_PAUSED || held.record.GetProgress().GetFailed() != 1 {
		t.Fatalf("a failure older than the rollout left it at %v", held.record)
	}
}

func TestAnAgentOutOfReachRefusingOrPinnedPausesNothing(t *testing.T) {
	h := newHarness(t, nil)
	fleet := newRolloutFleet(t, h, 3)
	evaluator := fleet.evaluator(t)
	everyone := canaryRollout("web-01", "web-02", "web-03", "web-04")
	everyone.Waves[0].Running = 1
	fleet.start(t, everyone)
	evaluator.Sweep(context.Background())

	unreachable := running("v0.2.0")
	unreachable.Update = &agentv1.Status_Update{Stage: agentv1.Status_Update_STAGE_FAILED, Version: "v0.3.0", Failure: agentv1.Status_Update_FAILURE_UNREACHABLE}
	refusing := running("v0.2.0")
	refusing.Update = &agentv1.Status_Update{Stage: agentv1.Status_Update_STAGE_FAILED, Version: "v0.3.0", Failure: agentv1.Status_Update_FAILURE_REFUSED}
	fleet.reports.say("web-01", unreachable)
	fleet.reports.say("web-02", refusing)
	fleet.reports.say("web-03", rolledBack("v0.2.0", "v0.3.0"))
	fleet.published.store.assigned["web-03"] = "v0.2.0"
	fleet.reports.say("web-04", running("v0.2.0"))
	fleet.reports.newest["web-04"].Compatibility.Updates.Enabled = false

	evaluator.Sweep(context.Background())
	held := fleet.rollouts.only(t)
	progress := held.record.GetProgress()
	if held.record.GetState() != updatev1.RolloutRecord_STATE_ACTIVE || progress.GetFailed() != 0 || progress.GetPending() != 1 ||
		progress.GetIneligible() != 2 || progress.GetPinned() != 1 || progress.GetReached() != 4 {
		t.Fatalf("the rollout stood at %v", held.record)
	}
}

func TestAReadingTakenBeforeAnOperatorsChangeIsNotWrittenOverIt(t *testing.T) {
	h := newHarness(t, nil)
	fleet := newRolloutFleet(t, h, 1)
	evaluator := fleet.evaluator(t)
	started := fleet.start(t, canaryRollout("web-01"))
	evaluator.Sweep(context.Background())

	fleet.reports.say("web-01", running("v0.3.0"))
	fleet.clock = time.Now().UTC().Add(2 * time.Hour)
	fleet.rollouts.settling = func() {
		fleet.rollouts.settling = nil
		fleet.change(t, started.GetRolloutId(), updatev1.RolloutChange_ACTION_PAUSE)
	}
	evaluator.Sweep(context.Background())
	if held := fleet.rollouts.only(t); held.record.GetState() != updatev1.RolloutRecord_STATE_PAUSED || held.record.GetWave() != 0 {
		t.Fatalf("a reading overtook the operator's pause: %v", held.record)
	}
}

func TestAStatusStoreThatCannotBeReadMovesNoRollout(t *testing.T) {
	h := newHarness(t, nil)
	fleet := newRolloutFleet(t, h, 1)
	evaluator := fleet.evaluator(t)
	fleet.start(t, canaryRollout("web-01"))
	fleet.reports.say("web-01", running("v0.3.0"))
	fleet.reports.unreached = errors.New("the status store is down")
	fleet.clock = time.Now().UTC().Add(2 * time.Hour)

	evaluator.Sweep(context.Background())
	if held := fleet.rollouts.only(t); held.record.GetWave() != 0 || held.record.GetProgress() != nil {
		t.Fatalf("a rollout moved on what the platform could not read: %v", held.record)
	}
	fleet.rollouts.unreached = errors.New("the registry is down")
	evaluator.Sweep(context.Background())
}

func TestARolloutOfAWholeTenantIsReadInPieces(t *testing.T) {
	h := newHarness(t, nil)
	fleet := newRolloutFleet(t, h, 1500)
	evaluator := fleet.evaluator(t)
	fleet.start(t, &updatev1.Rollout{TenantId: "default", Version: "v0.3.0", Waves: []*updatev1.Wave{{Percent: 100}}, Failures: 5})

	evaluator.Sweep(context.Background())
	if len(fleet.reports.asked) != 2 || len(fleet.reports.asked[0]) != 1000 || len(fleet.reports.asked[1]) != 501 {
		sizes := make([]int, len(fleet.reports.asked))
		for index, asked := range fleet.reports.asked {
			sizes[index] = len(asked)
		}
		t.Fatalf("the status store was asked about %v agents at a time", sizes)
	}
}
