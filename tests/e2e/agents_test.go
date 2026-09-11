package e2e_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

type registeredAgents struct {
	mutex        sync.Mutex
	held         map[string]*agentv1.Agent
	trail        map[string][]*agentv1.Transition
	certificates map[string][]*agentv1.CertificateRecord
	announced    map[string]uint64
}

func newRegisteredAgents() *registeredAgents {
	return &registeredAgents{
		held:         map[string]*agentv1.Agent{},
		trail:        map[string][]*agentv1.Transition{},
		certificates: map[string][]*agentv1.CertificateRecord{},
		announced:    map[string]uint64{},
	}
}

func (r *registeredAgents) Register(_ context.Context, asked *agentv1.Registration, actor string, at time.Time) (*agentv1.Agent, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, taken := r.held[asked.GetAgentId()]; taken {
		return nil, agent.ErrRegistered
	}
	registered, line, err := agent.Register(asked, actor, at)
	if err != nil {
		return nil, err
	}
	r.held[registered.GetAgentId()] = registered
	r.trail[registered.GetAgentId()] = []*agentv1.Transition{line}
	return registered, nil
}

func (r *registeredAgents) Agent(_ context.Context, id string, tenants []string) (*agentv1.Agent, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.lookup(id, tenants)
}

func (r *registeredAgents) lookup(id string, tenants []string) (*agentv1.Agent, error) {
	held, known := r.held[id]
	if !known {
		return nil, agent.ErrUnknown
	}
	for _, tenant := range tenants {
		if tenant == held.GetTenantId() {
			return held, nil
		}
	}
	return nil, agent.ErrUnknown
}

func (r *registeredAgents) Page(_ context.Context, _ *agentv1.Query, tenants []string) (*agentv1.Page, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	page := &agentv1.Page{}
	for id := range r.held {
		if one, err := r.lookup(id, tenants); err == nil {
			page.Agents = append(page.Agents, one)
		}
	}
	return page, nil
}

func (r *registeredAgents) History(_ context.Context, id string, tenants []string) (*agentv1.History, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, err := r.lookup(id, tenants); err != nil {
		return nil, err
	}
	return &agentv1.History{AgentId: id, Transitions: r.trail[id]}, nil
}

func (r *registeredAgents) Move(_ context.Context, id string, tenants []string, asked agent.Move) (*agentv1.Agent, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	held, err := r.lookup(id, tenants)
	if err != nil {
		return nil, err
	}
	return r.apply(held, asked)
}

func (r *registeredAgents) Renew(_ context.Context, id string, asked agent.Move) (*agentv1.Agent, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	held, known := r.held[id]
	if !known {
		return nil, agent.ErrUnknown
	}
	asked.Renewal = true
	return r.apply(held, asked)
}

func (r *registeredAgents) apply(held *agentv1.Agent, asked agent.Move) (*agentv1.Agent, error) {
	moved, line, err := agent.Apply(held, asked)
	if err != nil {
		return nil, err
	}
	id := moved.GetAgentId()
	r.held[id] = moved
	r.trail[id] = append(r.trail[id], line)
	if signed := agent.Certificate(moved, asked); signed != nil {
		r.certificates[id] = append([]*agentv1.CertificateRecord{signed}, r.certificates[id]...)
	}
	return moved, nil
}

func (r *registeredAgents) Certificates(_ context.Context, id string, tenants []string) (*agentv1.CertificateHistory, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, err := r.lookup(id, tenants); err != nil {
		return nil, err
	}
	return &agentv1.CertificateHistory{AgentId: id, Certificates: r.certificates[id]}, nil
}

func (r *registeredAgents) Outstanding(_ context.Context, _ int) ([]*agentv1.Admission, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var waiting []*agentv1.Admission
	for id, held := range r.held {
		if r.announced[id] < held.GetRevision() {
			waiting = append(waiting, agent.Admission(held))
		}
	}
	return waiting, nil
}

func (r *registeredAgents) Announced(_ context.Context, agentID string, revision uint64) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.announced[agentID] = revision
	return nil
}

type announcedAdmissions struct {
	mutex     sync.Mutex
	published []*agentv1.Admission
}

func (a *announcedAdmissions) Publish(_ context.Context, record *agentv1.Admission) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.published = append(a.published, record)
	return nil
}

func (a *announcedAdmissions) records() []*agentv1.Admission {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return append([]*agentv1.Admission(nil), a.published...)
}

// The whole administrative life of an agent over real mutual TLS: somebody
// registers it, the certificate it will present is recorded against it, and
// revoking it is attributable and reaches the data plane.
func TestAnAgentIsRegisteredBoundAndRevokedOverRealMutualTLS(t *testing.T) {
	plane := startControlAPI(t, nil)
	client := plane.caller(t, "e2e-admin")
	token := plane.open(t, client).GetToken()

	response, body := plane.send(t, client, http.MethodPost, control.AgentsPath, token, &agentv1.Registration{
		AgentId:      "e2e-agent-42",
		TenantId:     "default",
		Platform:     &agentv1.Platform{Os: "linux", Architecture: "amd64", Hostname: "web-42.default.internal"},
		AgentVersion: "2.0.0",
		Note:         "the first sensor of the estate",
	})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("registering was refused: %d %s", response.StatusCode, body)
	}
	var registered agentv1.Agent
	decode(t, body, &registered)
	if got, _ := agent.FromWire(registered.GetState()); got != agent.Pending {
		t.Fatalf("a registered agent is %s", got)
	}

	response, body = plane.send(t, client, http.MethodPost, "/v1/agents/e2e-agent-42/identity", token,
		&agentv1.BindingRequest{Identity: &agentv1.Identity{
			Subject:           "e2e-agent-42",
			Serial:            "0a1b2c3d4e5f6071",
			FingerprintSha256: strings.Repeat("7f", 32),
			IssuedAt:          timestamppb.New(time.Now().Add(-time.Minute)),
			ExpiresAt:         timestamppb.New(time.Now().Add(24 * time.Hour)),
		}})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("binding was refused: %d %s", response.StatusCode, body)
	}
	var bound agentv1.Agent
	decode(t, body, &bound)
	if got, _ := agent.FromWire(bound.GetState()); got != agent.Active {
		t.Fatalf("a bound agent is %s", got)
	}

	response, body = plane.send(t, client, http.MethodPost, "/v1/agents/e2e-agent-42/transition", token,
		&agentv1.TransitionRequest{To: agent.Revoked.Wire(), Note: "the host was rebuilt"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoking was refused: %d %s", response.StatusCode, body)
	}

	response, body = plane.send(t, client, http.MethodGet, "/v1/agents/e2e-agent-42/history", token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reading the trail was refused: %d %s", response.StatusCode, body)
	}
	var history agentv1.History
	decode(t, body, &history)
	if len(history.GetTransitions()) != 3 {
		t.Fatalf("the trail carries %d lines", len(history.GetTransitions()))
	}
	for _, line := range history.GetTransitions() {
		if line.GetActor() != "e2e-admin" {
			t.Fatalf("a lifecycle change is not attributed: %v", line)
		}
	}

	told := plane.told.records()
	if len(told) != 3 || told[len(told)-1].GetState() != agent.Revoked.Wire() {
		t.Fatalf("the data plane was told %v", told)
	}
}

func TestAnAnalystReadsTheRegistryAndCannotChangeIt(t *testing.T) {
	plane := startControlAPI(t, nil)
	admin := plane.caller(t, "e2e-admin")
	adminToken := plane.open(t, admin).GetToken()

	if response, body := plane.send(t, admin, http.MethodPost, control.AgentsPath, adminToken,
		&agentv1.Registration{AgentId: "e2e-agent-43", TenantId: "default"}); response.StatusCode != http.StatusCreated {
		t.Fatalf("registering was refused: %d %s", response.StatusCode, body)
	}

	analyst := plane.caller(t, "e2e-analyst")
	token := plane.open(t, analyst).GetToken()

	if response, body := plane.send(t, analyst, http.MethodGet, "/v1/agents/e2e-agent-43", token, nil); response.StatusCode != http.StatusOK {
		t.Fatalf("an analyst could not read the registry: %d %s", response.StatusCode, body)
	}
	response, _ := plane.send(t, analyst, http.MethodPost, "/v1/agents/e2e-agent-43/transition", token,
		&agentv1.TransitionRequest{To: agent.Decommissioned.Wire(), Note: "gone"})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("an analyst retired an agent: %d", response.StatusCode)
	}
}

// The gateway keeps authenticating from the certificate and reads no store; what
// it holds is the roster it was told, and a refused agent never reaches the
// backbone.
func TestTheGatewayRefusesAnAgentTheRegistryRevoked(t *testing.T) {
	roster := agent.NewRoster()
	running := startGateway(t, gatewayOptions{roster: roster})
	client := running.clientIn(t, "e2e-agent-42", "default")

	first := fixtures.Batch("roster-batch-1",
		fixtures.SSHAuthentication{EventID: "cccccccc-1111-4111-8111-cccccccccccc", Username: "root"}.Event())
	if response, body := running.send(t, client, first); response.StatusCode != http.StatusOK {
		t.Fatalf("a registered agent was refused: %d %s", response.StatusCode, body)
	}

	if err := roster.Apply(&agentv1.Admission{
		AgentId:  "e2e-agent-42",
		TenantId: "default",
		State:    agent.Revoked.Wire(),
		Revision: 2,
	}); err != nil {
		t.Fatalf("apply the revocation: %v", err)
	}

	second := fixtures.Batch("roster-batch-2",
		fixtures.SSHAuthentication{EventID: "dddddddd-2222-4222-8222-dddddddddddd", Username: "root"}.Event())
	response, body := running.send(t, client, second)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("a revoked agent was admitted: %d %s", response.StatusCode, body)
	}
	var rejection ingestv1.Rejection
	decode(t, body, &rejection)
	if rejection.GetCode() != "agent_not_admitted" {
		t.Fatalf("the refusal does not say why: %q", rejection.GetCode())
	}
	if published := len(running.backbone.published); published != 1 {
		t.Fatalf("%d events reached the backbone", published)
	}
}
