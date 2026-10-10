package control_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

// Enough of a policy store to prove the routes: the order a tenant's revisions
// must keep and the agents a policy may name are the store's to enforce, and
// this one enforces them the way the PostgreSQL one does.
type stubPolicies struct {
	agents    *stubAgents
	held      map[string][]agentpolicy.Accepted
	unreached error
}

func newStubPolicies(agents *stubAgents) *stubPolicies {
	return &stubPolicies{agents: agents, held: map[string][]agentpolicy.Accepted{}}
}

func (s *stubPolicies) Publish(_ context.Context, accepted agentpolicy.Accepted) (*policyv1.PublishedPolicy, error) {
	if s.unreached != nil {
		return nil, s.unreached
	}
	tenant := accepted.Record.GetTenantId()
	for _, before := range s.held[tenant] {
		if before.Record.GetRevision() >= accepted.Record.GetRevision() {
			return nil, fmt.Errorf("%w: %d", agentpolicy.ErrStale, before.Record.GetRevision())
		}
	}
	for _, id := range accepted.Targets {
		if registered, known := s.registered(id); !known || registered.GetTenantId() != tenant {
			return nil, fmt.Errorf("%w: %s", agentpolicy.ErrUnregistered, id)
		}
	}
	s.held[tenant] = append(s.held[tenant], accepted)
	return accepted.Record, nil
}

func (s *stubPolicies) registered(id string) (*agentv1.Agent, bool) {
	if s.agents == nil {
		return nil, false
	}
	held, known := s.agents.held[id]
	return held, known
}

func (s *stubPolicies) Page(_ context.Context, asked *policyv1.Query, tenants []string) (*policyv1.Page, error) {
	if s.unreached != nil {
		return nil, s.unreached
	}
	page := &policyv1.Page{}
	for tenant, published := range s.held {
		if !within(tenants, tenant) || (len(asked.GetTenantIds()) > 0 && !within(asked.GetTenantIds(), tenant)) {
			continue
		}
		for _, one := range published {
			if asked.GetAgentId() != "" && !slices.Contains(one.Targets, asked.GetAgentId()) {
				continue
			}
			listed, _ := proto.Clone(one.Record).(*policyv1.PublishedPolicy)
			listed.Policy = nil
			page.Policies = append(page.Policies, listed)
		}
	}
	return page, nil
}

func (s *stubPolicies) Policy(_ context.Context, tenant string, revision uint64, tenants []string) (*policyv1.PublishedPolicy, error) {
	if !within(tenants, tenant) {
		return nil, agentpolicy.ErrUnknown
	}
	for _, one := range s.held[tenant] {
		if one.Record.GetRevision() == revision {
			return one.Record, nil
		}
	}
	return nil, agentpolicy.ErrUnknown
}

func (s *stubPolicies) Served(_ context.Context, agentID string) (agentpolicy.Served, error) {
	if s.unreached != nil {
		return agentpolicy.Served{}, s.unreached
	}
	registered, known := s.registered(agentID)
	if !known {
		return agentpolicy.Served{}, agent.ErrUnknown
	}
	state, _ := agent.FromWire(registered.GetState())
	served := agentpolicy.Served{State: state}
	for _, one := range s.held[registered.GetTenantId()] {
		if slices.Contains(one.Targets, agentID) && one.Record.GetRevision() > served.Revision {
			served.Revision, served.Envelope, served.Digest = one.Record.GetRevision(), one.Served, one.Record.GetDigestSha256()
		}
	}
	return served, nil
}

func policyKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a policy signing key: %v", err)
	}
	return key
}

func accepting(t *testing.T, keys ...*ecdsa.PrivateKey) func() (*agentpolicy.Signers, error) {
	t.Helper()
	var encoded []byte
	for _, key := range keys {
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("encode a public key: %v", err)
		}
		encoded = append(encoded, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...)
	}
	return func() (*agentpolicy.Signers, error) { return agentpolicy.ParseSigners(encoded) }
}

func signedPolicy(t *testing.T, revision uint64, targets []string, keys ...*ecdsa.PrivateKey) *policyv1.SignedPolicy {
	t.Helper()
	at := time.Now().UTC()
	signing := make([]crypto.Signer, 0, len(keys))
	for _, key := range keys {
		signing = append(signing, key)
	}
	envelope, err := agentpolicy.Sign(&policyv1.Policy{
		SchemaVersion: agentpolicy.SchemaVersion,
		PolicyId:      "linux-web",
		Revision:      revision,
		Targets:       &policyv1.Targets{AgentIds: targets},
		IssuedAt:      timestamppb.New(at.Add(-time.Hour)),
		ExpiresAt:     timestamppb.New(at.Add(30 * 24 * time.Hour)),
		Settings:      &policyv1.Settings{LogLevel: policyv1.LogLevel_LOG_LEVEL_WARN},
	}, signing...)
	if err != nil {
		t.Fatalf("sign a policy: %v", err)
	}
	return envelope
}

func policyListener(t *testing.T, h *harness, held *stubAgents, published *stubPolicies, signers func() (*agentpolicy.Signers, error)) http.Handler {
	t.Helper()
	signing, bundle := testAuthority(t)
	handler, err := control.NewHandler(control.ServerOptions{
		Guard: h.guard, Sessions: h.sessions, Registry: h.registry,
		Rulesets: newStubRulesets(), Alerts: newStubAlerts(), Incidents: newStubIncidents(),
		Agents: held, Admissions: &stubAdmissions{}, Policies: published, PolicySigners: signers,
		Authority: signing, TrustBundle: bundle, CertificateLife: time.Hour,
		Metrics: h.metrics, Logger: slog.New(slog.DiscardHandler),
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-policies")),
	})
	if err != nil {
		t.Fatalf("build the routes: %v", err)
	}
	return handler
}

func agentFacing(t *testing.T, held *stubAgents, published *stubPolicies, limiter *ratelimit.Limiter) http.Handler {
	t.Helper()
	signing, bundle := testAuthority(t)
	handler, err := control.NewRenewalHandler(control.ServerOptions{
		Agents: held, Policies: published, PolicyLimiter: limiter,
		Authority: signing, TrustBundle: bundle, CertificateLife: time.Hour,
		Metrics:         control.NewMetrics(metrics.New("control-api-agent-policies")),
		Logger:          slog.New(slog.DiscardHandler),
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-agent-policy-routes")),
	})
	if err != nil {
		t.Fatalf("build the agent listener: %v", err)
	}
	return handler
}

func refusedWith(t *testing.T, recorder *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("answered %d, and %d was expected: %s", recorder.Code, status, recorder.Body)
	}
	var refusal controlv1.Refusal
	decode(t, recorder, &refusal)
	if refusal.GetCode() != code {
		t.Fatalf("refused with %q, and %q was expected: %s", refusal.GetCode(), code, refusal.GetDetail())
	}
}

func TestAnAdministratorPublishesASignedPolicyIntoATenantTheyHold(t *testing.T) {
	h, held, key := newHarness(t, nil), newStubAgents(), policyKey(t)
	published := newStubPolicies(held)
	handler := policyListener(t, h, held, published, accepting(t, key))

	envelope := signedPolicy(t, 7, []string{"web-01"}, key)
	recorder := call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", open(t, h, "dev-admin"),
		&policyv1.Publication{TenantId: "default", Policy: envelope, Note: "quieter web servers"})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("publishing answered %d: %s", recorder.Code, recorder.Body)
	}

	var answer policyv1.PublishedPolicy
	decode(t, recorder, &answer)
	id, err := agentpolicy.KeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("name the key: %v", err)
	}
	served, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode the envelope: %v", err)
	}
	switch {
	case answer.GetRevision() != 7 || answer.GetTenantId() != "default" || answer.GetPolicyId() != "linux-web":
		t.Fatalf("the platform recorded %v", &answer)
	case !slices.Equal(answer.GetSignedBy(), []string{id}):
		t.Fatalf("the policy is recorded as signed by %v", answer.GetSignedBy())
	case answer.GetPublishedBy() != "dev-admin" || answer.GetNote() != "quieter web servers" || answer.GetTargets() != 1:
		t.Fatalf("the publication is attributed as %v", &answer)
	case answer.GetDigestSha256() != agentpolicy.Digest(served):
		t.Fatalf("the digest %s is not the one of the envelope served", answer.GetDigestSha256())
	case answer.GetPolicy() != nil:
		t.Fatal("publishing answered with the envelope it was sent")
	case len(published.held["default"]) != 1:
		t.Fatalf("the store holds %d policies", len(published.held["default"]))
	}
}

func TestPublishingAPolicyNeedsToWriteAgentsInItsTenant(t *testing.T) {
	h, held, key := newHarness(t, nil), newStubAgents(), policyKey(t)
	published := newStubPolicies(held)
	handler := policyListener(t, h, held, published, accepting(t, key))

	refusedWith(t, call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-analyst", open(t, h, "dev-analyst"),
		&policyv1.Publication{TenantId: "default", Policy: signedPolicy(t, 1, []string{"web-01"}, key)}),
		http.StatusForbidden, control.CodeForbidden)
	refusedWith(t, call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", open(t, h, "dev-admin"),
		&policyv1.Publication{TenantId: "another", Policy: signedPolicy(t, 1, []string{"web-01"}, key)}),
		http.StatusForbidden, control.CodeForbidden)
	if len(published.held) != 0 {
		t.Fatalf("a refused publication was stored: %v", published.held)
	}
}

func TestAPolicyNoAcceptedKeySignedIsNeverPublished(t *testing.T) {
	h, held, key, stranger := newHarness(t, nil), newStubAgents(), policyKey(t), policyKey(t)
	published := newStubPolicies(held)
	handler := policyListener(t, h, held, published, accepting(t, key))
	token := open(t, h, "dev-admin")

	refusedWith(t, call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", token,
		&policyv1.Publication{TenantId: "default", Policy: signedPolicy(t, 1, []string{"web-01"}, stranger)}),
		http.StatusUnprocessableEntity, control.CodePolicyUnsigned)

	changed := signedPolicy(t, 1, []string{"web-01"}, key)
	changed.Payload[len(changed.Payload)-1] ^= 0x01
	refusedWith(t, call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", token,
		&policyv1.Publication{TenantId: "default", Policy: changed}),
		http.StatusUnprocessableEntity, control.CodePolicyUnsigned)

	refusedWith(t, call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", token,
		&policyv1.Publication{TenantId: "default"}),
		http.StatusUnprocessableEntity, control.CodeMalformedPolicy)

	if len(published.held) != 0 {
		t.Fatalf("an unsigned policy was stored: %v", published.held)
	}
}

func TestAPolicyOutsideItsLifetimeOrTheContractIsNeverPublished(t *testing.T) {
	h, held, key := newHarness(t, nil), newStubAgents(), policyKey(t)
	handler := policyListener(t, h, held, newStubPolicies(held), accepting(t, key))
	token := open(t, h, "dev-admin")

	expired, err := agentpolicy.Sign(&policyv1.Policy{
		SchemaVersion: agentpolicy.SchemaVersion, PolicyId: "linux-web", Revision: 1,
		Targets:   &policyv1.Targets{AgentIds: []string{"web-01"}},
		IssuedAt:  timestamppb.New(time.Now().Add(-48 * time.Hour)),
		ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour)),
	}, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	refusedWith(t, call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", token,
		&policyv1.Publication{TenantId: "default", Policy: expired}),
		http.StatusUnprocessableEntity, control.CodePolicyExpired)

	refusedWith(t, call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", token,
		&policyv1.Publication{TenantId: "default", Policy: signedPolicy(t, 1, nil, key)}),
		http.StatusUnprocessableEntity, control.CodeMalformedPolicy)
}

func TestARevisionNotAboveItsTenantsHighestIsRefused(t *testing.T) {
	h, held, key := newHarness(t, nil), newStubAgents(), policyKey(t)
	handler := policyListener(t, h, held, newStubPolicies(held), accepting(t, key))
	token := open(t, h, "dev-admin")

	if recorder := call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", token,
		&policyv1.Publication{TenantId: "default", Policy: signedPolicy(t, 5, []string{"web-01"}, key)}); recorder.Code != http.StatusCreated {
		t.Fatalf("the first revision answered %d: %s", recorder.Code, recorder.Body)
	}
	for _, revision := range []uint64{5, 4} {
		refusedWith(t, call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", token,
			&policyv1.Publication{TenantId: "default", Policy: signedPolicy(t, revision, []string{"web-01"}, key)}),
			http.StatusConflict, control.CodePolicyStale)
	}
}

func TestAPolicyNamingAnAgentOutsideItsTenantIsRefused(t *testing.T) {
	h, held, key := newHarness(t, nil), newStubAgents(), policyKey(t)
	handler := policyListener(t, h, held, newStubPolicies(held), accepting(t, key))

	refusedWith(t, call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", open(t, h, "dev-admin"),
		&policyv1.Publication{TenantId: "default", Policy: signedPolicy(t, 1, []string{"web-01", "db-07"}, key)}),
		http.StatusUnprocessableEntity, control.CodePolicyUnregistered)
}

func TestAControlPlaneGivenNoSignersPublishesNothing(t *testing.T) {
	h, held, key := newHarness(t, nil), newStubAgents(), policyKey(t)
	handler := policyListener(t, h, held, newStubPolicies(held), nil)

	refusedWith(t, call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", open(t, h, "dev-admin"),
		&policyv1.Publication{TenantId: "default", Policy: signedPolicy(t, 1, []string{"web-01"}, key)}),
		http.StatusServiceUnavailable, control.CodePoliciesUnconfigured)
}

func TestPoliciesAreReadWithinTheTenantsACallerHolds(t *testing.T) {
	h, held, key := newHarness(t, nil), newStubAgents(), policyKey(t)
	published := newStubPolicies(held)
	handler := policyListener(t, h, held, published, accepting(t, key))

	envelope := signedPolicy(t, 3, []string{"web-01"}, key)
	if recorder := call(t, handler, http.MethodPost, control.AgentPoliciesPath, "dev-admin", open(t, h, "dev-admin"),
		&policyv1.Publication{TenantId: "default", Policy: envelope}); recorder.Code != http.StatusCreated {
		t.Fatalf("publishing answered %d: %s", recorder.Code, recorder.Body)
	}
	analyst := open(t, h, "dev-analyst")

	listed := call(t, handler, http.MethodPost, control.AgentPolicySearch, "dev-analyst", analyst, &policyv1.Query{})
	var page policyv1.Page
	decode(t, listed, &page)
	if len(page.GetPolicies()) != 1 || page.GetPolicies()[0].GetPolicy() != nil {
		t.Fatalf("the analyst listed %v", &page)
	}
	elsewhere := call(t, handler, http.MethodPost, control.AgentPolicySearch, "dev-analyst", analyst, &policyv1.Query{TenantIds: []string{"another"}})
	decode(t, elsewhere, &page)
	if len(page.GetPolicies()) != 0 {
		t.Fatalf("naming a tenant the analyst does not hold listed %v", &page)
	}

	described := call(t, handler, http.MethodGet, "/v1/agents/policies/default/3", "dev-analyst", analyst, nil)
	var one policyv1.PublishedPolicy
	decode(t, described, &one)
	if described.Code != http.StatusOK || !proto.Equal(one.GetPolicy(), envelope) {
		t.Fatalf("describing the policy answered %d with %v", described.Code, one.GetPolicy())
	}
	for _, path := range []string{"/v1/agents/policies/default/4", "/v1/agents/policies/another/3", "/v1/agents/policies/default/three"} {
		refusedWith(t, call(t, handler, http.MethodGet, path, "dev-analyst", analyst, nil), http.StatusNotFound, control.CodeUnknownPolicy)
	}
}

func ask(t *testing.T, handler http.Handler, subject, unchanged string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, control.PolicyPath, nil)
	r.TLS = request(t, subject, "").TLS
	if unchanged != "" {
		r.Header.Set("If-None-Match", unchanged)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

func publish(t *testing.T, published *stubPolicies, envelope *policyv1.SignedPolicy, keys ...*ecdsa.PrivateKey) agentpolicy.Accepted {
	t.Helper()
	signers, err := accepting(t, keys...)()
	if err != nil {
		t.Fatalf("read the signers: %v", err)
	}
	accepted, err := agentpolicy.Accept(&policyv1.Publication{TenantId: "default", Policy: envelope}, signers, "dev-admin", time.Now())
	if err != nil {
		t.Fatalf("accept the policy: %v", err)
	}
	if _, err := published.Publish(t.Context(), accepted); err != nil {
		t.Fatalf("publish the policy: %v", err)
	}
	return accepted
}

func TestAnAgentIsHandedTheNewestPolicyNamingItAsItWasRecorded(t *testing.T) {
	held, key := newStubAgents(), policyKey(t)
	published := newStubPolicies(held)
	publish(t, published, signedPolicy(t, 2, []string{"web-01"}, key), key)
	newest := publish(t, published, signedPolicy(t, 3, []string{"web-01"}, key), key)
	if _, err := held.Register(t.Context(), &agentv1.Registration{AgentId: "web-02", TenantId: "default"}, "dev-admin", time.Now()); err != nil {
		t.Fatalf("register another agent: %v", err)
	}
	publish(t, published, signedPolicy(t, 4, []string{"web-02"}, key), key)

	recorder := ask(t, agentFacing(t, held, published, nil), "web-01", "")
	switch {
	case recorder.Code != http.StatusOK:
		t.Fatalf("the agent was answered %d: %s", recorder.Code, recorder.Body)
	case !slices.Equal(recorder.Body.Bytes(), newest.Served):
		t.Fatal("the agent was handed something other than the newest envelope naming it")
	case recorder.Header().Get("ETag") != strconv.Quote(newest.Record.GetDigestSha256()):
		t.Fatalf("the envelope was tagged %q", recorder.Header().Get("ETag"))
	case recorder.Header().Get("Content-Type") != control.ContentType:
		t.Fatalf("the envelope was answered as %q", recorder.Header().Get("Content-Type"))
	}
}

func TestAnAgentHoldingThePolicyItWouldBeHandedIsToldNothingChanged(t *testing.T) {
	held, key := newStubAgents(), policyKey(t)
	published := newStubPolicies(held)
	current := publish(t, published, signedPolicy(t, 1, []string{"web-01"}, key), key)
	handler := agentFacing(t, held, published, nil)
	tag := strconv.Quote(current.Record.GetDigestSha256())

	for _, asked := range []string{tag, "W/" + tag, `"elsewhere", ` + tag, "*"} {
		if recorder := ask(t, handler, "web-01", asked); recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 {
			t.Fatalf("asking with %q was answered %d with %d bytes", asked, recorder.Code, recorder.Body.Len())
		}
	}
	if recorder := ask(t, handler, "web-01", `"elsewhere"`); recorder.Code != http.StatusOK {
		t.Fatalf("asking with another tag was answered %d", recorder.Code)
	}
}

func TestAnAgentIsHandedNothingItShouldNotHave(t *testing.T) {
	held, key := newStubAgents(), policyKey(t)
	published := newStubPolicies(held)
	handler := agentFacing(t, held, published, nil)

	refusedWith(t, ask(t, handler, "web-01", ""), http.StatusNotFound, control.CodeNoPolicy)
	refusedWith(t, ask(t, handler, "web-77", ""), http.StatusNotFound, control.CodeUnknownAgent)
	if recorder := ask(t, handler, "", ""); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("an unidentified connection was answered %d", recorder.Code)
	}

	publish(t, published, signedPolicy(t, 1, []string{"web-01"}, key), key)
	if _, err := held.Move(t.Context(), "web-01", []string{"default"}, agent.Move{
		To: agent.Disabled, Note: "the machine is being rebuilt", Actor: "dev-admin", At: held.clock,
	}); err != nil {
		t.Fatalf("disable the agent: %v", err)
	}
	refusedWith(t, ask(t, handler, "web-01", ""), http.StatusForbidden, control.CodeNotAdmitted)
}

func TestAnAgentAskingForItsPolicyTooOftenIsRefused(t *testing.T) {
	held, key := newStubAgents(), policyKey(t)
	published := newStubPolicies(held)
	publish(t, published, signedPolicy(t, 1, []string{"web-01"}, key), key)
	handler := agentFacing(t, held, published, ratelimit.NewLimiter(0.001, 1, 16))

	if recorder := ask(t, handler, "web-01", ""); recorder.Code != http.StatusOK {
		t.Fatalf("the first request was answered %d", recorder.Code)
	}
	refusedWith(t, ask(t, handler, "web-01", ""), http.StatusTooManyRequests, control.CodeRateLimited)
}
