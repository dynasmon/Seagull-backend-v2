package control_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Enough of a registry to prove the routes: what the listener owns is who may
// ask, which tenant they may ask about, what it answers with and what it tells
// the data plane afterwards.
type stubAgents struct {
	held      map[string]*agentv1.Agent
	trail     map[string][]*agentv1.Transition
	announced map[string]uint64
	unreached error
	clock     time.Time
}

func newStubAgents() *stubAgents {
	registered, line, err := agent.Register(&agentv1.Registration{
		AgentId:  "web-01",
		TenantId: "default",
		Platform: &agentv1.Platform{Os: "linux", Architecture: "amd64"},
	}, "dev-admin", time.Date(2026, 9, 6, 9, 0, 0, 0, time.UTC))
	if err != nil {
		panic(err)
	}
	return &stubAgents{
		held:      map[string]*agentv1.Agent{registered.GetAgentId(): registered},
		trail:     map[string][]*agentv1.Transition{registered.GetAgentId(): {line}},
		announced: map[string]uint64{},
		clock:     time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC),
	}
}

func (s *stubAgents) Register(_ context.Context, asked *agentv1.Registration, actor string, at time.Time) (*agentv1.Agent, error) {
	if s.unreached != nil {
		return nil, s.unreached
	}
	if _, taken := s.held[asked.GetAgentId()]; taken {
		return nil, agent.ErrRegistered
	}
	registered, line, err := agent.Register(asked, actor, at)
	if err != nil {
		return nil, err
	}
	s.held[registered.GetAgentId()] = registered
	s.trail[registered.GetAgentId()] = []*agentv1.Transition{line}
	return registered, nil
}

func (s *stubAgents) Agent(_ context.Context, id string, tenants []string) (*agentv1.Agent, error) {
	if s.unreached != nil {
		return nil, s.unreached
	}
	held, known := s.held[id]
	if !known || !within(tenants, held.GetTenantId()) {
		return nil, agent.ErrUnknown
	}
	return held, nil
}

func (s *stubAgents) Page(_ context.Context, _ *agentv1.Query, tenants []string) (*agentv1.Page, error) {
	if s.unreached != nil {
		return nil, s.unreached
	}
	page := &agentv1.Page{}
	for _, held := range s.held {
		if within(tenants, held.GetTenantId()) {
			page.Agents = append(page.Agents, held)
		}
	}
	return page, nil
}

func (s *stubAgents) History(ctx context.Context, id string, tenants []string) (*agentv1.History, error) {
	if _, err := s.Agent(ctx, id, tenants); err != nil {
		return nil, err
	}
	return &agentv1.History{AgentId: id, Transitions: s.trail[id]}, nil
}

func (s *stubAgents) Move(ctx context.Context, id string, tenants []string, asked agent.Move) (*agentv1.Agent, error) {
	held, err := s.Agent(ctx, id, tenants)
	if err != nil {
		return nil, err
	}
	moved, line, err := agent.Apply(held, asked)
	if err != nil {
		return nil, err
	}
	s.held[id] = moved
	s.trail[id] = append(s.trail[id], line)
	return moved, nil
}

func (s *stubAgents) Outstanding(_ context.Context, _ int) ([]*agentv1.Admission, error) {
	if s.unreached != nil {
		return nil, s.unreached
	}
	var waiting []*agentv1.Admission
	for _, held := range s.held {
		if s.announced[held.GetAgentId()] < held.GetRevision() {
			waiting = append(waiting, agent.Admission(held))
		}
	}
	return waiting, nil
}

func (s *stubAgents) Announced(_ context.Context, agentID string, revision uint64) error {
	s.announced[agentID] = revision
	return nil
}

func within(tenants []string, tenant string) bool {
	for _, held := range tenants {
		if held == tenant {
			return true
		}
	}
	return false
}

type stubAdmissions struct {
	published []*agentv1.Admission
	unreached error
}

func (s *stubAdmissions) Publish(_ context.Context, record *agentv1.Admission) error {
	if s.unreached != nil {
		return s.unreached
	}
	s.published = append(s.published, record)
	return nil
}

func registry(t *testing.T, h *harness, held *stubAgents, told *stubAdmissions) http.Handler {
	t.Helper()
	return listenerReading(t, h, held, told, nil)
}

func listenerReading(t *testing.T, h *harness, held *stubAgents, told *stubAdmissions, seen control.Liveness) http.Handler {
	t.Helper()
	return listenerRegistering(t, h, newStubRulesets(), newStubAlerts(), newStubIncidents(), held, told, seen)
}

func TestReadingAnAgentNeedsThePermissionAndRegisteringOneNeedsMore(t *testing.T) {
	h := newHarness(t, nil)
	handler := registry(t, h, newStubAgents(), &stubAdmissions{})

	analyst := session(t, handler, "dev-analyst")
	if recorder := call(t, handler, http.MethodGet, "/v1/agents/web-01", "dev-analyst", analyst, nil); recorder.Code != http.StatusOK {
		t.Fatalf("reading an agent answered an analyst %d: %s", recorder.Code, recorder.Body)
	}

	refused := call(t, handler, http.MethodPost, control.AgentsPath, "dev-analyst", analyst,
		&agentv1.Registration{AgentId: "db-07", TenantId: "default"})
	if refused.Code != http.StatusForbidden {
		t.Fatalf("an analyst registered an agent: %d", refused.Code)
	}

	engineer := session(t, handler, "dev-engineer")
	if recorder := call(t, handler, http.MethodGet, "/v1/agents/web-01", "dev-engineer", engineer, nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("an engineer read an agent: %d", recorder.Code)
	}
}

func TestAnAgentIsRegisteredOnlyIntoATenantTheCallerHolds(t *testing.T) {
	h := newHarness(t, nil)
	handler := registry(t, h, newStubAgents(), &stubAdmissions{})
	operator := session(t, handler, "dev-admin")

	response := call(t, handler, http.MethodPost, control.AgentsPath, "dev-admin", operator, &agentv1.Registration{
		AgentId: "db-07", TenantId: "somebody-else",
	})
	if response.Code != http.StatusForbidden {
		t.Fatalf("an agent was registered into another estate: %d", response.Code)
	}

	allowed := call(t, handler, http.MethodPost, control.AgentsPath, "dev-admin", operator, &agentv1.Registration{
		AgentId: "db-07", TenantId: "default",
	})
	if allowed.Code != http.StatusCreated {
		t.Fatalf("registering into a held tenant was refused: %d %s", allowed.Code, allowed.Body)
	}

	var registered agentv1.Agent
	if err := proto.Unmarshal(allowed.Body.Bytes(), &registered); err != nil {
		t.Fatalf("read the registration: %v", err)
	}
	if got, _ := agent.FromWire(registered.GetState()); got != agent.Pending {
		t.Fatalf("a registered agent is %s", got)
	}
}

func TestRegisteringTheSameAgentTwiceIsRefusedRatherThanOverwriting(t *testing.T) {
	h := newHarness(t, nil)
	handler := registry(t, h, newStubAgents(), &stubAdmissions{})

	operator := session(t, handler, "dev-admin")
	response := call(t, handler, http.MethodPost, control.AgentsPath, "dev-admin", operator,
		&agentv1.Registration{AgentId: "web-01", TenantId: "default"})
	if response.Code != http.StatusConflict {
		t.Fatalf("a registered agent was registered again: %d", response.Code)
	}
}

func TestAnAgentIsRetiredThroughTheApiAndTheTrailRecordsWhoDidIt(t *testing.T) {
	h := newHarness(t, nil)
	held, told := newStubAgents(), &stubAdmissions{}
	handler := registry(t, h, held, told)
	operator := session(t, handler, "dev-admin")

	response := call(t, handler, http.MethodPost, "/v1/agents/web-01/transition", "dev-admin", operator,
		&agentv1.TransitionRequest{To: agent.Revoked.Wire(), Note: "the key leaked"})
	if response.Code != http.StatusOK {
		t.Fatalf("revoking was refused: %d %s", response.Code, response.Body)
	}

	trail := call(t, handler, http.MethodGet, "/v1/agents/web-01/history", "dev-admin", operator, nil)
	var history agentv1.History
	if err := proto.Unmarshal(trail.Body.Bytes(), &history); err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	last := history.GetTransitions()[len(history.GetTransitions())-1]
	if last.GetTo() != agent.Revoked.Wire() || last.GetActor() != "dev-admin" || last.GetNote() != "the key leaked" {
		t.Fatalf("the trail does not say who revoked it and why: %v", last)
	}
}

func TestWhatWasDecidedReachesTheDataPlane(t *testing.T) {
	h := newHarness(t, nil)
	held, told := newStubAgents(), &stubAdmissions{}
	handler := registry(t, h, held, told)

	response := call(t, handler, http.MethodPost, "/v1/agents/web-01/transition", "dev-admin",
		session(t, handler, "dev-admin"), &agentv1.TransitionRequest{To: agent.Disabled.Wire(), Note: "noisy"})
	if response.Code != http.StatusOK {
		t.Fatalf("disabling was refused: %d %s", response.Code, response.Body)
	}
	if len(told.published) != 1 {
		t.Fatalf("the data plane was told %d times", len(told.published))
	}
	if told.published[0].GetState() != agent.Disabled.Wire() || told.published[0].GetAgentId() != "web-01" {
		t.Fatalf("the wrong thing was published: %v", told.published[0])
	}
	if held.announced["web-01"] != told.published[0].GetRevision() {
		t.Fatal("the registry does not record that the decision was announced")
	}
}

// A backbone that refused the record must not make the caller believe nothing
// happened: the decision is recorded, the answer is given, and the announcer
// carries it when the backbone comes back.
func TestADecisionIsRecordedEvenWhenTheDataPlaneCannotBeTold(t *testing.T) {
	h := newHarness(t, nil)
	held := newStubAgents()
	told := &stubAdmissions{unreached: errors.New("the backbone is unreachable")}
	handler := registry(t, h, held, told)

	response := call(t, handler, http.MethodPost, "/v1/agents/web-01/transition", "dev-admin",
		session(t, handler, "dev-admin"), &agentv1.TransitionRequest{To: agent.Revoked.Wire(), Note: "the key leaked"})
	if response.Code != http.StatusOK {
		t.Fatalf("a revocation was lost because the backbone was down: %d", response.Code)
	}

	waiting, err := held.Outstanding(context.Background(), 10)
	if err != nil {
		t.Fatalf("read what is outstanding: %v", err)
	}
	if len(waiting) == 0 {
		t.Fatal("a decision the data plane was never told about is not outstanding")
	}
}

func TestBindingACertificateMakesAPendingAgentActive(t *testing.T) {
	h := newHarness(t, nil)
	held, told := newStubAgents(), &stubAdmissions{}
	handler := registry(t, h, held, told)

	response := call(t, handler, http.MethodPost, "/v1/agents/web-01/identity", "dev-admin",
		session(t, handler, "dev-admin"), &agentv1.BindingRequest{Identity: &agentv1.Identity{
			Subject:           "web-01",
			Serial:            "3fa10b7c9d2e4f61",
			FingerprintSha256: strings.Repeat("ab", 32),
			ExpiresAt:         timestamppb.New(time.Now().Add(90 * 24 * time.Hour)),
		}})
	if response.Code != http.StatusOK {
		t.Fatalf("binding was refused: %d %s", response.Code, response.Body)
	}

	var bound agentv1.Agent
	if err := proto.Unmarshal(response.Body.Bytes(), &bound); err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	if got, _ := agent.FromWire(bound.GetState()); got != agent.Active {
		t.Fatalf("a bound agent is %s", got)
	}
}

func TestACertificateNamingAnotherAgentIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	handler := registry(t, h, newStubAgents(), &stubAdmissions{})

	response := call(t, handler, http.MethodPost, "/v1/agents/web-01/identity", "dev-admin",
		session(t, handler, "dev-admin"), &agentv1.BindingRequest{Identity: &agentv1.Identity{
			Subject:           "db-07",
			Serial:            "3fa10b7c9d2e4f61",
			FingerprintSha256: strings.Repeat("ab", 32),
			ExpiresAt:         timestamppb.New(time.Now().Add(time.Hour)),
		}})
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a certificate for another agent was bound: %d %s", response.Code, response.Body)
	}
}

func TestAnAgentOutsideTheCallersTenantsIsNotThere(t *testing.T) {
	h := newHarness(t, nil)
	held := newStubAgents()
	held.held["web-01"].TenantId = "somebody-else"
	handler := registry(t, h, held, &stubAdmissions{})

	response := call(t, handler, http.MethodGet, "/v1/agents/web-01", "dev-admin", session(t, handler, "dev-admin"), nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("an agent in another estate was readable: %d", response.Code)
	}
}

func TestARegistryThatDoesNotAnswerIsNotACallerMistake(t *testing.T) {
	h := newHarness(t, nil)
	held := newStubAgents()
	handler := registry(t, h, held, &stubAdmissions{})

	operator := session(t, handler, "dev-admin")
	held.unreached = errors.New("the registry is unreachable")
	response := call(t, handler, http.MethodGet, "/v1/agents/web-01", "dev-admin", operator, nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unreachable registry answered %d", response.Code)
	}
}

func TestTheAnnouncerCarriesWhatTheBackboneRefusedEarlier(t *testing.T) {
	h := newHarness(t, nil)
	held, told := newStubAgents(), &stubAdmissions{}
	handler := registry(t, h, held, told)

	response := call(t, handler, http.MethodPost, "/v1/agents/web-01/transition", "dev-admin",
		session(t, handler, "dev-admin"), &agentv1.TransitionRequest{To: agent.Revoked.Wire(), Note: "the key leaked"})
	if response.Code != http.StatusOK {
		t.Fatalf("revoking was refused: %d", response.Code)
	}

	waiting, err := held.Outstanding(context.Background(), 10)
	if err != nil {
		t.Fatalf("read what is outstanding: %v", err)
	}
	if len(waiting) != 0 {
		t.Fatalf("%d decisions are still outstanding after a successful publish", len(waiting))
	}
}

type stubLiveness struct {
	seen      map[string]time.Time
	unreached error
}

func (s *stubLiveness) LastSeen(_ context.Context, agents, tenants []string) (map[string]time.Time, error) {
	if s.unreached != nil {
		return nil, s.unreached
	}
	answered := map[string]time.Time{}
	for _, agentID := range agents {
		if at, known := s.seen[agentID]; known && len(tenants) > 0 {
			answered[agentID] = at
		}
	}
	return answered, nil
}

func TestWhenAnAgentWasLastHeardFromIsAnsweredBesideWhatWasDecided(t *testing.T) {
	h := newHarness(t, nil)
	heard := time.Date(2026, 9, 6, 11, 30, 0, 0, time.UTC)
	handler := listenerReading(t, h, newStubAgents(), &stubAdmissions{},
		&stubLiveness{seen: map[string]time.Time{"web-01": heard}})

	response := call(t, handler, http.MethodGet, "/v1/agents/web-01", "dev-admin",
		session(t, handler, "dev-admin"), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("reading an agent answered %d", response.Code)
	}

	var one agentv1.Agent
	if err := proto.Unmarshal(response.Body.Bytes(), &one); err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	if one.GetLastSeen().AsTime() != heard {
		t.Fatalf("the agent was last heard from %s", one.GetLastSeen().AsTime())
	}
}

// The registry holds what was decided; where telemetry landed is a second store,
// and losing it costs the caller a column rather than the answer.
func TestATelemetryStoreThatDoesNotAnswerStillLeavesTheAgentReadable(t *testing.T) {
	h := newHarness(t, nil)
	handler := listenerReading(t, h, newStubAgents(), &stubAdmissions{},
		&stubLiveness{unreached: errors.New("the telemetry store is unreachable")})

	response := call(t, handler, http.MethodGet, "/v1/agents/web-01", "dev-admin",
		session(t, handler, "dev-admin"), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("an unreachable telemetry store made an agent unreadable: %d", response.Code)
	}

	var one agentv1.Agent
	if err := proto.Unmarshal(response.Body.Bytes(), &one); err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	if one.GetLastSeen() != nil {
		t.Fatal("a liveness nobody could read was answered anyway")
	}
}
