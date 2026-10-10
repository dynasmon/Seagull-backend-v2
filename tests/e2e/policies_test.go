package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

type publishedPolicies struct {
	mutex  sync.Mutex
	agents *registeredAgents
	held   map[string][]agentpolicy.Accepted
}

func newPublishedPolicies(agents *registeredAgents) *publishedPolicies {
	return &publishedPolicies{agents: agents, held: map[string][]agentpolicy.Accepted{}}
}

func (p *publishedPolicies) tenantOf(id string) (string, agent.State, bool) {
	p.agents.mutex.Lock()
	defer p.agents.mutex.Unlock()
	held, known := p.agents.held[id]
	if !known {
		return "", "", false
	}
	state, _ := agent.FromWire(held.GetState())
	return held.GetTenantId(), state, true
}

func (p *publishedPolicies) Publish(_ context.Context, accepted agentpolicy.Accepted) (*policyv1.PublishedPolicy, error) {
	tenant := accepted.Record.GetTenantId()
	for _, id := range accepted.Targets {
		if registered, _, known := p.tenantOf(id); !known || registered != tenant {
			return nil, fmt.Errorf("%w: %s", agentpolicy.ErrUnregistered, id)
		}
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	for _, before := range p.held[tenant] {
		if before.Record.GetRevision() >= accepted.Record.GetRevision() {
			return nil, agentpolicy.ErrStale
		}
	}
	p.held[tenant] = append(p.held[tenant], accepted)
	return accepted.Record, nil
}

func (p *publishedPolicies) Page(_ context.Context, _ *policyv1.Query, tenants []string) (*policyv1.Page, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	page := &policyv1.Page{}
	for _, tenant := range tenants {
		for _, one := range p.held[tenant] {
			page.Policies = append(page.Policies, one.Record)
		}
	}
	return page, nil
}

func (p *publishedPolicies) Policy(_ context.Context, tenant string, revision uint64, tenants []string) (*policyv1.PublishedPolicy, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	for _, one := range p.held[tenant] {
		if slices.Contains(tenants, tenant) && one.Record.GetRevision() == revision {
			return one.Record, nil
		}
	}
	return nil, agentpolicy.ErrUnknown
}

func (p *publishedPolicies) Served(_ context.Context, agentID string) (agentpolicy.Served, error) {
	tenant, state, known := p.tenantOf(agentID)
	if !known {
		return agentpolicy.Served{}, agent.ErrUnknown
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	served := agentpolicy.Served{State: state}
	for _, one := range p.held[tenant] {
		if slices.Contains(one.Targets, agentID) && one.Record.GetRevision() > served.Revision {
			served.Revision, served.Envelope, served.Digest = one.Record.GetRevision(), one.Served, one.Record.GetDigestSha256()
		}
	}
	return served, nil
}

func signersOf(t *testing.T, key *ecdsa.PrivateKey) func() (*agentpolicy.Signers, error) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode the policy signer: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return func() (*agentpolicy.Signers, error) { return agentpolicy.ParseSigners(encoded) }
}

func (c *controlPlane) publishPolicy(t *testing.T, client *http.Client, token string, revision uint64, targets ...string) {
	t.Helper()
	envelope, err := agentpolicy.Sign(&policyv1.Policy{
		SchemaVersion: agentpolicy.SchemaVersion,
		PolicyId:      "e2e-servers",
		Revision:      revision,
		Targets:       &policyv1.Targets{AgentIds: targets},
		IssuedAt:      timestamppb.New(time.Now().Add(-time.Minute)),
		ExpiresAt:     timestamppb.New(time.Now().Add(24 * time.Hour)),
		Settings:      &policyv1.Settings{LogLevel: policyv1.LogLevel_LOG_LEVEL_DEBUG},
	}, c.policyKey)
	if err != nil {
		t.Fatalf("sign the policy: %v", err)
	}
	response, body := c.send(t, client, http.MethodPost, control.AgentPoliciesPath, token,
		&policyv1.Publication{TenantId: "default", Policy: envelope})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("publishing revision %d was refused: %d %s", revision, response.StatusCode, body)
	}
}

func (c *controlPlane) askForPolicy(t *testing.T, client *http.Client, tag string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://"+c.renewalAddress+control.PolicyPath, nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	if tag != "" {
		request.Header.Set("If-None-Match", tag)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("ask for the policy: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	return response, body
}

// Over real mutual TLS: an operator publishes a policy they signed, and the
// agent it names is handed it on the listener it renews on, verifies it under
// the key it was given, and is told nothing changed until a newer revision is
// published.
func TestAnAgentIsHandedThePolicyAnOperatorSignedOverRealMutualTLS(t *testing.T) {
	plane := startControlAPI(t, nil)
	operator := plane.caller(t, "e2e-admin")
	token := plane.open(t, operator).GetToken()
	plane.register(t, operator, token, "e2e-agent-80")
	plane.register(t, operator, token, "e2e-agent-81")
	key, requestPEM := keyAndRequest(t, "e2e-agent-80")
	named := plane.agentClient(t, key, plane.issue(t, operator, token, "e2e-agent-80", requestPEM))
	otherKey, otherRequest := keyAndRequest(t, "e2e-agent-81")
	unnamed := plane.agentClient(t, otherKey, plane.issue(t, operator, token, "e2e-agent-81", otherRequest))

	if response, body := plane.askForPolicy(t, named, ""); response.StatusCode != http.StatusNotFound || refusalCode(t, body) != control.CodeNoPolicy {
		t.Fatalf("an agent no policy names was answered %d %s", response.StatusCode, refusalCode(t, body))
	}

	plane.publishPolicy(t, operator, token, 1, "e2e-agent-80")
	response, body := plane.askForPolicy(t, named, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the agent the policy names was answered %d: %s", response.StatusCode, body)
	}
	var envelope policyv1.SignedPolicy
	if err := proto.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("read the envelope: %v", err)
	}
	signers, err := signersOf(t, plane.policyKey)()
	if err != nil {
		t.Fatalf("read the signers: %v", err)
	}
	verified, err := signers.Verify(&envelope)
	if err != nil || verified.Policy.GetRevision() != 1 {
		t.Fatalf("the agent could not verify what it was handed: %v", err)
	}
	tag := response.Header.Get("ETag")
	if again, _ := plane.askForPolicy(t, named, tag); again.StatusCode != http.StatusNotModified {
		t.Fatalf("asking again with %s was answered %d", tag, again.StatusCode)
	}
	if other, body := plane.askForPolicy(t, unnamed, ""); other.StatusCode != http.StatusNotFound || refusalCode(t, body) != control.CodeNoPolicy {
		t.Fatalf("an agent the policy does not name was answered %d", other.StatusCode)
	}

	plane.publishPolicy(t, operator, token, 2, "e2e-agent-80", "e2e-agent-81")
	newer, body := plane.askForPolicy(t, named, tag)
	if newer.StatusCode != http.StatusOK || newer.Header.Get("ETag") == tag {
		t.Fatalf("a newer revision was answered %d with %s", newer.StatusCode, newer.Header.Get("ETag"))
	}
	if err := proto.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("read the newer envelope: %v", err)
	}
	if verified, err := signers.Verify(&envelope); err != nil || verified.Policy.GetRevision() != 2 {
		t.Fatalf("the newer envelope did not verify as revision 2: %v", err)
	}
	if other, _ := plane.askForPolicy(t, unnamed, ""); other.StatusCode != http.StatusOK {
		t.Fatalf("an agent the newer revision names was answered %d", other.StatusCode)
	}
}

func TestAnOperatorKeyCannotAskForAnAgentsPolicy(t *testing.T) {
	plane := startControlAPI(t, nil)
	operator := plane.caller(t, "e2e-admin")
	request, err := http.NewRequest(http.MethodGet, "https://"+plane.renewalAddress+control.PolicyPath, nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	if response, err := operator.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatalf("an operator certificate reached the agent listener and was answered %d", response.StatusCode)
	}
}
