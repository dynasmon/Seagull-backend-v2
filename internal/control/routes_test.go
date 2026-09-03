package control_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

func routes(t *testing.T, h *harness) http.Handler {
	t.Helper()
	return routesWith(t, h, newStubRulesets())
}

func routesWith(t *testing.T, h *harness, store control.Rulesets) http.Handler {
	t.Helper()
	return listener(t, h, store, newStubAlerts())
}

func listener(t *testing.T, h *harness, store control.Rulesets, raised control.Alerts) http.Handler {
	t.Helper()
	return listenerTelling(t, h, store, raised, newStubIncidents())
}

func listenerTelling(t *testing.T, h *harness, store control.Rulesets, raised control.Alerts, told control.Incidents) http.Handler {
	t.Helper()

	handler, err := control.NewHandler(control.ServerOptions{
		Guard:           h.guard,
		Sessions:        h.sessions,
		Registry:        h.registry,
		Rulesets:        store,
		Alerts:          raised,
		Incidents:       told,
		Metrics:         h.metrics,
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-routes")),
	})
	if err != nil {
		t.Fatalf("build the routes: %v", err)
	}
	return handler
}

// Enough of a ruleset store to prove the routes: what the listener owns is who
// may ask, what it answers with and which status it answers at, and none of
// that is the rule language's business.
type stubRulesets struct {
	valid     bool
	held      bool
	versions  map[string]*rulesetv1.Version
	active    string
	unreached error

	publishedBy string
	activatedBy string
	activated   string
}

func newStubRulesets() *stubRulesets {
	return &stubRulesets{
		valid:    true,
		held:     true,
		versions: map[string]*rulesetv1.Version{"ab01": {Id: "ab01", PublishedBy: "dev-engineer"}},
		active:   "ab01",
	}
}

func (s *stubRulesets) validation() *rulesetv1.ValidationResponse {
	if !s.valid {
		return &rulesetv1.ValidationResponse{Faults: []*rulesetv1.Fault{{Source: "rules.yml", Line: 4, Reason: "is not part of a rule file"}}}
	}
	return &rulesetv1.ValidationResponse{Valid: true, RulesetId: "cd02", Rules: 2, Running: 1}
}

func (s *stubRulesets) Validate([]*rulesetv1.Document) *rulesetv1.ValidationResponse {
	return s.validation()
}

func (s *stubRulesets) Check([]*rulesetv1.Document) (*rulesetv1.ValidationResponse, *rulesetv1.CheckResponse) {
	if !s.valid {
		return s.validation(), nil
	}
	return s.validation(), &rulesetv1.CheckResponse{Held: s.held, Rules: 2, Cases: 3}
}

func (s *stubRulesets) Publish(_ context.Context, _ *rulesetv1.PublishRequest, by string, _ time.Time) (*rulesetv1.PublishResponse, error) {
	if s.unreached != nil {
		return nil, s.unreached
	}
	validation, report := s.Check(nil)
	answer := &rulesetv1.PublishResponse{RulesetId: validation.GetRulesetId(), Validation: validation, Check: report}
	if !validation.GetValid() || !report.GetHeld() {
		return answer, nil
	}
	s.publishedBy = by
	s.versions[validation.GetRulesetId()] = &rulesetv1.Version{Id: validation.GetRulesetId(), PublishedBy: by}
	answer.Published = true
	return answer, nil
}

func (s *stubRulesets) List() *rulesetv1.VersionList {
	listed := make([]*rulesetv1.Summary, 0, len(s.versions))
	for id, version := range s.versions {
		listed = append(listed, &rulesetv1.Summary{Id: id, PublishedBy: version.GetPublishedBy(), Active: id == s.active})
	}
	return &rulesetv1.VersionList{Versions: listed, Active: &rulesetv1.Active{RulesetId: s.active}}
}

func (s *stubRulesets) Version(id string) (*rulesetv1.Version, bool) {
	version, published := s.versions[id]
	return version, published
}

func (s *stubRulesets) Activate(_ context.Context, id, _, by string, _ time.Time) (*rulesetv1.ActivationResponse, error) {
	if _, published := s.versions[id]; !published {
		return nil, control.ErrUnknownRuleset
	}
	replaced := s.active
	s.active, s.activatedBy, s.activated = id, by, id
	return &rulesetv1.ActivationResponse{Active: &rulesetv1.Active{RulesetId: id, ActivatedBy: by}, Replaced: replaced}, nil
}

func session(t *testing.T, handler http.Handler, subject string) string {
	t.Helper()

	recorder := call(t, handler, http.MethodPost, control.SessionPath, subject, "", &controlv1.SessionRequest{})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("open a session for %q: %d %s", subject, recorder.Code, recorder.Body)
	}

	var opened controlv1.SessionResponse
	decode(t, recorder, &opened)
	return opened.GetToken()
}

func call(t *testing.T, handler http.Handler, method, path, subject, token string, body proto.Message) *httptest.ResponseRecorder {
	t.Helper()

	var payload []byte
	if body != nil {
		encoded, err := proto.Marshal(body)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		payload = encoded
	}

	r := httptest.NewRequest(method, path, bytes.NewReader(payload))
	r.TLS = request(t, subject, "").TLS
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

func decode(t *testing.T, recorder *httptest.ResponseRecorder, into proto.Message) {
	t.Helper()
	if err := proto.Unmarshal(recorder.Body.Bytes(), into); err != nil {
		t.Fatalf("decode a %d answer: %v", recorder.Code, err)
	}
}

func TestOpeningASessionAnswersWhatTheCallerHolds(t *testing.T) {
	h := newHarness(t, nil)
	handler := routes(t, h)

	recorder := call(t, handler, http.MethodPost, control.SessionPath, "dev-analyst", "", &controlv1.SessionRequest{})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("opening a session answered %d: %s", recorder.Code, recorder.Body)
	}

	var answer controlv1.SessionResponse
	decode(t, recorder, &answer)

	if answer.GetToken() == "" {
		t.Fatal("no token was returned")
	}
	if answer.GetSession().GetGrant().GetSubject() != "dev-analyst" {
		t.Errorf("the grant names %q", answer.GetSession().GetGrant().GetSubject())
	}
	if tenants := answer.GetSession().GetGrant().GetTenants(); len(tenants) != 1 || tenants[0] != "default" {
		t.Errorf("the grant covers %v", tenants)
	}

	held := map[controlv1.Resource]map[controlv1.Action]bool{}
	for _, permission := range answer.GetSession().GetGrant().GetPermissions() {
		if held[permission.GetResource()] == nil {
			held[permission.GetResource()] = map[controlv1.Action]bool{}
		}
		held[permission.GetResource()][permission.GetAction()] = true
	}
	if !held[controlv1.Resource_RESOURCE_EVENTS][controlv1.Action_ACTION_READ] {
		t.Error("the analyst is not told they may read events")
	}
	if held[controlv1.Resource_RESOURCE_RULESETS][controlv1.Action_ACTION_WRITE] {
		t.Error("the analyst is told they may write rulesets")
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("a token was answered with Cache-Control %q", recorder.Header().Get("Cache-Control"))
	}
}

func TestTheSessionRoutesNeedWhatTheyDeclare(t *testing.T) {
	h := newHarness(t, nil)
	handler := routes(t, h)

	for name, call := range map[string]struct {
		method string
		path   string
	}{
		"describing a session": {http.MethodGet, control.SessionPath},
		"ending a session":     {http.MethodDelete, control.SessionPath},
		"listing sessions":     {http.MethodGet, control.SessionsPath},
	} {
		r := httptest.NewRequest(call.method, call.path, nil)
		r.TLS = request(t, "dev-analyst", "").TLS

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)

		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s without a session answered %d", name, recorder.Code)
		}
	}
}

func TestACallerEndsTheirOwnSessionAndNobodyElsesWithoutThePermission(t *testing.T) {
	h := newHarness(t, nil)
	handler := routes(t, h)

	analyst := open(t, h, "dev-analyst")
	victim, _, err := h.sessions.Open("dev-admin", authz.Fingerprint(certificate("dev-admin")), now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	refused := call(t, handler, http.MethodDelete, control.SessionPath, "dev-analyst", analyst,
		&controlv1.RevocationRequest{SessionId: victim.ID()})
	if refused.Code != http.StatusForbidden {
		t.Errorf("the analyst ended another caller's session: %d", refused.Code)
	}
	if h.sessions.Live() != 2 {
		t.Errorf("%d sessions are live after a refused revocation", h.sessions.Live())
	}

	own := call(t, handler, http.MethodDelete, control.SessionPath, "dev-analyst", analyst, &controlv1.RevocationRequest{})
	if own.Code != http.StatusOK {
		t.Fatalf("the analyst could not end their own session: %d", own.Code)
	}
	var answer controlv1.RevocationResponse
	decode(t, own, &answer)
	if answer.GetRevoked() != 1 {
		t.Errorf("ending the caller's own session reported %d", answer.GetRevoked())
	}
}

func TestAnAdministratorEndsAnotherCallersSession(t *testing.T) {
	h := newHarness(t, nil)
	handler := routes(t, h)

	admin := open(t, h, "dev-admin")
	victim, victimToken, err := h.sessions.Open("dev-analyst", authz.Fingerprint(certificate("dev-analyst")), now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	recorder := call(t, handler, http.MethodDelete, control.SessionPath, "dev-admin", admin,
		&controlv1.RevocationRequest{SessionId: victim.ID()})
	if recorder.Code != http.StatusOK {
		t.Fatalf("the administrator was refused: %d %s", recorder.Code, recorder.Body)
	}
	if _, err := h.sessions.Verify(victimToken, authz.Fingerprint(certificate("dev-analyst")), now); err == nil {
		t.Error("the ended session is still spendable")
	}
}

func TestListingAnotherCallersSessionsNeedsThePermission(t *testing.T) {
	h := newHarness(t, nil)
	handler := routes(t, h)

	analyst := open(t, h, "dev-analyst")
	admin := open(t, h, "dev-admin")

	if recorder := call(t, handler, http.MethodGet, control.SessionsPath+"?subject=dev-admin", "dev-analyst", analyst, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("the analyst listed another caller's sessions: %d", recorder.Code)
	}

	own := call(t, handler, http.MethodGet, control.SessionsPath, "dev-analyst", analyst, nil)
	if own.Code != http.StatusOK {
		t.Fatalf("the analyst could not list their own sessions: %d", own.Code)
	}
	var listed controlv1.SessionList
	decode(t, own, &listed)
	if len(listed.GetSessions()) != 1 {
		t.Errorf("the analyst holds %d sessions", len(listed.GetSessions()))
	}

	elevated := call(t, handler, http.MethodGet, control.SessionsPath+"?subject=dev-analyst", "dev-admin", admin, nil)
	if elevated.Code != http.StatusOK {
		t.Errorf("the administrator was refused: %d", elevated.Code)
	}
}

func TestTheDescriptorStillNeedsACertificate(t *testing.T) {
	h := newHarness(t, nil)
	handler := routes(t, h)

	r := httptest.NewRequest(http.MethodGet, control.DescriptorPath, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("the descriptor answered %d without a certificate", recorder.Code)
	}

	if answered := call(t, handler, http.MethodGet, control.DescriptorPath, "dev-analyst", "", nil); answered.Code != http.StatusOK {
		t.Errorf("the descriptor answered %d to an authenticated caller", answered.Code)
	}
}

func TestABodyLargerThanTheRouteReadsIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	handler := routes(t, h)

	oversized := bytes.Repeat([]byte{0}, control.MaxBodyBytes+1)
	r := httptest.NewRequest(http.MethodPost, control.SessionPath, bytes.NewReader(oversized))
	r.TLS = request(t, "dev-analyst", "").TLS

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversized body answered %d", recorder.Code)
	}
}

func TestARouteWithoutARequirementCannotBeServed(t *testing.T) {
	h := newHarness(t, nil)

	if _, err := control.NewHandler(control.ServerOptions{Guard: h.guard, Sessions: h.sessions, Registry: h.registry, Metrics: h.metrics}); err == nil {
		t.Error("routes were built without instrumentation")
	}
	if _, err := control.NewServer(control.ServerOptions{Guard: h.guard}); err == nil {
		t.Error("a listener was built without TLS")
	}
}
