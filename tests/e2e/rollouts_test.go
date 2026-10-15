package e2e_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// What the PostgreSQL store enforces of rollouts, held in memory: one in force
// per tenant, taken over by the next, and a reading written only while the
// rollout stands where it was read.
type startedRollouts struct {
	mutex   sync.Mutex
	agents  *registeredAgents
	updates *publishedUpdates
	held    map[string]*startedRollout
}

type startedRollout struct {
	record       *updatev1.RolloutRecord
	changes      int64
	failing      []string
	acknowledged map[string]bool
}

func newStartedRollouts(agents *registeredAgents, updates *publishedUpdates) *startedRollouts {
	return &startedRollouts{agents: agents, updates: updates, held: map[string]*startedRollout{}}
}

func (r *startedRollouts) Start(_ context.Context, accepted agentupdate.AcceptedRollout) (*updatev1.RolloutRecord, error) {
	rollout := accepted.Rollout()
	if !r.updates.names(rollout.GetVersion()) {
		return nil, fmt.Errorf("%w: %s", agentupdate.ErrUncataloged, rollout.GetVersion())
	}
	named := slices.Clone(rollout.GetAgentIds())
	for _, wave := range rollout.GetWaves() {
		named = append(named, wave.GetAgentIds()...)
	}
	for _, id := range named {
		if tenant, _, known := r.updates.state(id); !known || tenant != rollout.GetTenantId() {
			return nil, fmt.Errorf("%w: %s", agentupdate.ErrUnregistered, id)
		}
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, other := range r.held {
		if other.record.GetRollout().GetTenantId() == rollout.GetTenantId() && agentupdate.InForce(other.record.GetState()) {
			other.record.State = updatev1.RolloutRecord_STATE_SUPERSEDED
			other.changes++
		}
	}
	r.held[accepted.ID()] = &startedRollout{record: proto.CloneOf(accepted.Record), acknowledged: map[string]bool{}}
	return accepted.Record, nil
}

func (r *startedRollouts) Change(_ context.Context, accepted agentupdate.AcceptedChange) (*updatev1.RolloutRecord, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	held, known := r.held[accepted.RolloutID]
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

func (r *startedRollouts) Page(_ context.Context, _ *updatev1.RolloutQuery, tenants []string) (*updatev1.RolloutPage, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	page := &updatev1.RolloutPage{}
	for _, held := range r.held {
		if slices.Contains(tenants, held.record.GetRollout().GetTenantId()) {
			page.Rollouts = append(page.Rollouts, proto.CloneOf(held.record))
		}
	}
	return page, nil
}

func (r *startedRollouts) Rollout(_ context.Context, tenant, id string, tenants []string) (*updatev1.RolloutRecord, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	held, known := r.held[id]
	if !known || held.record.GetRollout().GetTenantId() != tenant || !slices.Contains(tenants, tenant) {
		return nil, agentupdate.ErrRolloutUnknown
	}
	return proto.CloneOf(held.record), nil
}

func (r *startedRollouts) InForce(context.Context) ([]agentupdate.Held, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	var found []agentupdate.Held
	for _, held := range r.held {
		if agentupdate.InForce(held.record.GetState()) {
			found = append(found, agentupdate.Held{
				Record: proto.CloneOf(held.record), Named: len(held.record.GetRollout().GetAgentIds()) > 0, Changes: held.changes,
			})
		}
	}
	return found, nil
}

func (r *startedRollouts) Reach(_ context.Context, held agentupdate.Held) (agentupdate.Reach, error) {
	r.mutex.Lock()
	stored := r.held[held.Record.GetRolloutId()]
	named := slices.Clone(stored.record.GetRollout().GetAgentIds())
	reach := agentupdate.Reach{Pinned: map[string]bool{}, Acknowledged: map[string]bool{}}
	for id := range stored.acknowledged {
		reach.Acknowledged[id] = true
	}
	r.mutex.Unlock()

	r.agents.mutex.Lock()
	for id, registered := range r.agents.held {
		state, _ := agent.FromWire(registered.GetState())
		if registered.GetTenantId() == held.Record.GetRollout().GetTenantId() && state.Admits() &&
			(!held.Named || slices.Contains(named, id)) {
			reach.Agents = append(reach.Agents, id)
		}
	}
	r.agents.mutex.Unlock()
	slices.Sort(reach.Agents)
	for _, id := range reach.Agents {
		if r.updates.assignedTo(id) != "" {
			reach.Pinned[id] = true
		}
	}
	return reach, nil
}

func (r *startedRollouts) Settle(_ context.Context, settled agentupdate.Settled) (bool, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	held := r.held[settled.Record.GetRolloutId()]
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

func (r *startedRollouts) Catalog(context.Context) ([]byte, error) {
	r.updates.mutex.Lock()
	defer r.updates.mutex.Unlock()
	if newest := r.updates.newest(); newest != nil {
		return newest.Served(), nil
	}
	return nil, nil
}

// The rollout in force in a tenant, and whether it may move the agent.
func (r *startedRollouts) inForce(tenant, agentID string) (*updatev1.RolloutRecord, bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, held := range r.held {
		if held.record.GetRollout().GetTenantId() == tenant && agentupdate.InForce(held.record.GetState()) {
			named := held.record.GetRollout().GetAgentIds()
			return proto.CloneOf(held.record), len(named) == 0 || slices.Contains(named, agentID)
		}
	}
	return nil, false
}

// The newest status report of each agent, as a status store would hold it.
type reportedStatus struct {
	mutex  sync.Mutex
	newest map[string]agentstatus.Report
}

func (s *reportedStatus) Newest(_ context.Context, agents, tenants []string) (map[string]agentstatus.Report, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	found := map[string]agentstatus.Report{}
	for _, id := range agents {
		if report, known := s.newest[id]; known && slices.Contains(tenants, report.Status.GetOrigin().GetTenantId()) {
			found[id] = report
		}
	}
	return found, nil
}

func (s *reportedStatus) say(id string, report *agentv1.Status) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.newest[id] = agentstatus.Report{Received: time.Now(), Status: report}
}

func originOf(agentID string) *eventv1.Origin {
	return &eventv1.Origin{AgentId: agentID, TenantId: "default"}
}

func (c *controlPlane) offered(t *testing.T, client *http.Client) string {
	t.Helper()
	response, body := c.agentGet(t, client, control.UpdatePath, "")
	expect(t, response, body, http.StatusOK, "asking whether to update")
	var offer updatev1.Offer
	if err := proto.Unmarshal(body, &offer); err != nil {
		t.Fatalf("read the offer: %v", err)
	}
	return offer.GetVersion()
}

func (c *controlPlane) steer(t *testing.T, client *http.Client, token, id string, action updatev1.RolloutChange_Action) *updatev1.RolloutRecord {
	t.Helper()
	response, body := c.send(t, client, http.MethodPost, control.UpdateRolloutChangesPath, token,
		&updatev1.RolloutChange{TenantId: "default", RolloutId: id, Action: action, Note: "looked at the canary"})
	expect(t, response, body, http.StatusOK, action.String())
	var changed updatev1.RolloutRecord
	decode(t, body, &changed)
	return &changed
}

func (c *controlPlane) rollout(t *testing.T, client *http.Client, token, id string) *updatev1.RolloutRecord {
	t.Helper()
	response, body := c.send(t, client, http.MethodGet, "/v1/agents/update/rollouts/default/"+id, token, nil)
	expect(t, response, body, http.StatusOK, "reading the rollout")
	var held updatev1.RolloutRecord
	decode(t, body, &held)
	return &held
}

// Over real mutual TLS: an operator rolls a release out with a canary, the
// canary reports that it went back from it, and the platform pauses the
// rollout on its own, asking nothing more of any agent; once the operator
// resumes it and opens the next wave, an agent is asked to run the release
// exactly as its place in the rollout says, and renewing its certificate under
// another key does not move it.
func TestARolloutPausesOnItsCanaryAndMovesAgentsByTheirPlaceOverRealMutualTLS(t *testing.T) {
	plane := startControlAPI(t, nil)
	operator := plane.caller(t, "e2e-admin")
	token := plane.open(t, operator).GetToken()

	clients := map[string]*http.Client{}
	requests := map[string][]byte{}
	for _, id := range []string{"e2e-agent-80", "e2e-agent-81", "e2e-agent-82", "e2e-agent-83"} {
		plane.register(t, operator, token, id)
		key, requestPEM := keyAndRequest(t, id)
		clients[id], requests[id] = plane.agentClient(t, key, plane.issue(t, operator, token, id, requestPEM)), requestPEM
	}

	running, target := []byte("!<arch>\ndebian-binary   the package of v0.2.0"), []byte("!<arch>\ndebian-binary   the package of v0.3.0")
	for _, given := range [][]byte{running, target} {
		if response := plane.give(t, operator, token, given); response.StatusCode != http.StatusCreated {
			t.Fatalf("giving a package was answered %d", response.StatusCode)
		}
	}
	response, body := plane.send(t, operator, http.MethodPost, control.UpdateCatalogsPath, token,
		&updatev1.CatalogPublication{Catalog: releaseCatalog(t, 1, plane.updateKey, releaseOfPackage("v0.2.0", running), releaseOfPackage("v0.3.0", target))})
	expect(t, response, body, http.StatusCreated, "publishing catalog 1")

	response, body = plane.send(t, operator, http.MethodPost, control.UpdateRolloutsPath, token, &updatev1.Rollout{
		TenantId: "default",
		Version:  "v0.3.0",
		Waves:    []*updatev1.Wave{{AgentIds: []string{"e2e-agent-80"}}, {Percent: 50}, {Percent: 100}},
		Failures: 1,
	})
	expect(t, response, body, http.StatusCreated, "starting the rollout")
	var started updatev1.RolloutRecord
	decode(t, body, &started)

	if got := plane.offered(t, clients["e2e-agent-80"]); got != "v0.3.0" {
		t.Fatalf("the canary is asked to run %q", got)
	}
	if got := plane.offered(t, clients["e2e-agent-81"]); got != "" {
		t.Fatalf("an agent no open wave reaches is asked to run %q", got)
	}

	plane.reported.say("e2e-agent-80", &agentv1.Status{
		Origin: originOf("e2e-agent-80"),
		Build:  &agentv1.Status_Build{Version: "v0.2.0", Os: "linux", Architecture: "amd64"},
		Update: &agentv1.Status_Update{Stage: agentv1.Status_Update_STAGE_ROLLED_BACK, Version: "v0.3.0", Failure: agentv1.Status_Update_FAILURE_UNHEALTHY},
	})
	deadline := time.Now().Add(10 * time.Second)
	for plane.rollout(t, operator, token, started.GetRolloutId()).GetState() != updatev1.RolloutRecord_STATE_PAUSED {
		if time.Now().After(deadline) {
			t.Fatal("the rollout did not pause on the canary that went back from its release")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if paused := plane.rollout(t, operator, token, started.GetRolloutId()); paused.GetChangedBy() != agentupdate.Platform ||
		paused.GetProgress().GetFailed() != 1 || paused.GetWave() != 0 {
		t.Fatalf("the paused rollout reads %v", paused)
	}
	for id, client := range clients {
		if got := plane.offered(t, client); got != "" {
			t.Fatalf("with the rollout paused %s is asked to run %q", id, got)
		}
	}

	plane.steer(t, operator, token, started.GetRolloutId(), updatev1.RolloutChange_ACTION_RESUME)
	plane.steer(t, operator, token, started.GetRolloutId(), updatev1.RolloutChange_ACTION_ADVANCE)
	for _, id := range []string{"e2e-agent-81", "e2e-agent-82", "e2e-agent-83"} {
		want := ""
		if agentupdate.Place(started.GetRolloutId(), id) < 5000 {
			want = "v0.3.0"
		}
		if got := plane.offered(t, clients[id]); got != want {
			t.Fatalf("at place %d %s is asked to run %q", agentupdate.Place(started.GetRolloutId(), id), id, got)
		}
		key, requestPEM := keyAndRequest(t, id)
		response, body := plane.renew(t, clients[id], requestPEM)
		expect(t, response, body, http.StatusCreated, "renewing "+id)
		var issued agentv1.IssuedCertificate
		decode(t, body, &issued)
		if got := plane.offered(t, plane.agentClient(t, key, &issued)); got != want {
			t.Fatalf("under a renewed certificate %s is asked to run %q", id, got)
		}
	}
	if resumed := plane.rollout(t, operator, token, started.GetRolloutId()); resumed.GetState() != updatev1.RolloutRecord_STATE_ACTIVE ||
		resumed.GetWave() != 1 {
		t.Fatalf("the resumed rollout reads %v", resumed)
	}
}
