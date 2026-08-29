package control_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

var now = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

func policy(t *testing.T) *authz.Policy {
	t.Helper()

	analyst, err := authz.NewRole("analyst", "reads", []authz.Permission{
		{Resource: authz.Events, Action: authz.Read},
		{Resource: authz.Detections, Action: authz.Read},
	})
	if err != nil {
		t.Fatalf("build a role: %v", err)
	}
	engineer, err := authz.NewRole("engineer", "writes and publishes rules", []authz.Permission{
		{Resource: authz.Detections, Action: authz.Read},
		{Resource: authz.Rulesets, Action: authz.Read},
		{Resource: authz.Rulesets, Action: authz.Write},
	})
	if err != nil {
		t.Fatalf("build a role: %v", err)
	}
	administrator, err := authz.NewRole("administrator", "administers", []authz.Permission{
		{Resource: authz.Events, Action: authz.Read},
		{Resource: authz.Rulesets, Action: authz.Write},
		{Resource: authz.Sessions, Action: authz.Read},
		{Resource: authz.Sessions, Action: authz.Delete},
	})
	if err != nil {
		t.Fatalf("build a role: %v", err)
	}

	bindings := make([]authz.Binding, 0, 3)
	for subject, roles := range map[string][]string{
		"dev-analyst":  {"analyst"},
		"dev-engineer": {"engineer"},
		"dev-admin":    {"administrator"},
	} {
		binding, err := authz.NewBinding(subject, roles, []string{"default"})
		if err != nil {
			t.Fatalf("bind %q: %v", subject, err)
		}
		bindings = append(bindings, binding)
	}

	compiled, err := authz.Compile([]authz.Role{analyst, engineer, administrator}, bindings)
	if err != nil {
		t.Fatalf("compile the policy: %v", err)
	}
	return compiled
}

type harness struct {
	guard    *control.Guard
	sessions *control.Sessions
	registry *control.Registry
	metrics  *control.Metrics
}

func newHarness(t *testing.T, limiter *ratelimit.Limiter) *harness {
	t.Helper()

	instruments := control.NewMetrics(metrics.New("control-api-test"))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	registry, err := control.NewRegistry(control.RegistryOptions{
		Source:  control.SourceFunc(func() (*authz.Policy, error) { return policy(t), nil }),
		Metrics: instruments,
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("build a registry: %v", err)
	}

	key, err := authz.RandomSessionKey()
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	issuer, err := authz.NewIssuer(key, 15*time.Minute)
	if err != nil {
		t.Fatalf("build an issuer: %v", err)
	}
	sessions, err := control.NewSessions(control.SessionOptions{Issuer: issuer})
	if err != nil {
		t.Fatalf("build a session store: %v", err)
	}

	guard, err := control.NewGuard(control.GuardOptions{
		Sessions: sessions,
		Registry: registry,
		Limiter:  limiter,
		Metrics:  instruments,
		Logger:   logger,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("build a guard: %v", err)
	}
	return &harness{guard: guard, sessions: sessions, registry: registry, metrics: instruments}
}

func certificate(commonName string) *x509.Certificate {
	return &x509.Certificate{Raw: []byte(commonName), Subject: pkix.Name{CommonName: commonName}}
}

func request(t *testing.T, subject, token string) *http.Request {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/v1/anything", nil)
	if subject != "" {
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate(subject)}}}
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func open(t *testing.T, h *harness, subject string) string {
	t.Helper()
	_, token, err := h.sessions.Open(subject, authz.Fingerprint(certificate(subject)), now)
	if err != nil {
		t.Fatalf("open a session for %q: %v", subject, err)
	}
	return token
}

func reached(h *harness, requirement control.Requirement, r *http.Request) (int, string, bool) {
	arrived := false
	handler := h.guard.Handle("test", requirement, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		arrived = true
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)

	code := ""
	var refusal controlv1.Refusal
	if proto.Unmarshal(recorder.Body.Bytes(), &refusal) == nil {
		code = refusal.GetCode()
	}
	return recorder.Code, code, arrived
}

func TestAConnectionNobodyAuthenticatedReachesNothing(t *testing.T) {
	h := newHarness(t, nil)

	for name, requirement := range map[string]control.Requirement{
		"a certificate route": control.Certificate(),
		"a session route":     control.Session(),
		"a permission route":  control.Permits(authz.Events, authz.Read),
	} {
		status, code, arrived := reached(h, requirement, request(t, "", ""))
		if arrived {
			t.Errorf("%s ran the handler without a certificate", name)
		}
		if status != http.StatusUnauthorized || code != control.CodeNoCertificate {
			t.Errorf("%s answered %d %q", name, status, code)
		}
	}
}

func TestTheZeroRequirementRefuses(t *testing.T) {
	h := newHarness(t, nil)

	status, code, arrived := reached(h, control.Requirement{}, request(t, "dev-admin", open(t, newHarness(t, nil), "dev-admin")))
	if arrived {
		t.Error("a route that says nothing about what it requires ran its handler")
	}
	if status != http.StatusInternalServerError || code != control.CodeUnguarded {
		t.Errorf("an unguarded route answered %d %q", status, code)
	}
}

func TestASessionIsNeededForEverythingButOpeningOne(t *testing.T) {
	h := newHarness(t, nil)

	if status, _, arrived := reached(h, control.Certificate(), request(t, "dev-analyst", "")); !arrived || status != http.StatusOK {
		t.Errorf("opening a session with a certificate answered %d", status)
	}
	for name, requirement := range map[string]control.Requirement{
		"a session route":    control.Session(),
		"a permission route": control.Permits(authz.Events, authz.Read),
	} {
		status, code, arrived := reached(h, requirement, request(t, "dev-analyst", ""))
		if arrived {
			t.Errorf("%s ran without a session", name)
		}
		if status != http.StatusUnauthorized || code != control.CodeNoSession {
			t.Errorf("%s answered %d %q", name, status, code)
		}
	}
}

func TestACallerReachesOnlyWhatTheyHold(t *testing.T) {
	h := newHarness(t, nil)
	token := open(t, h, "dev-analyst")

	if status, _, arrived := reached(h, control.Permits(authz.Events, authz.Read), request(t, "dev-analyst", token)); !arrived {
		t.Errorf("the analyst was refused what the policy grants: %d", status)
	}

	status, code, arrived := reached(h, control.Permits(authz.Rulesets, authz.Write), request(t, "dev-analyst", token))
	if arrived {
		t.Error("the analyst wrote rulesets")
	}
	if status != http.StatusForbidden || code != control.CodeForbidden {
		t.Errorf("the analyst was refused with %d %q", status, code)
	}
}

func TestACallerThePolicyDoesNotMentionIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	token := open(t, h, "mallory")

	status, code, arrived := reached(h, control.Session(), request(t, "mallory", token))
	if arrived {
		t.Error("an unbound caller reached a handler")
	}
	if status != http.StatusForbidden || code != control.CodeNoGrant {
		t.Errorf("an unbound caller was refused with %d %q", status, code)
	}
}

// A token lifted off a log is worthless without the key it was minted against.
func TestATokenCannotBeSpentOnAnotherConnection(t *testing.T) {
	h := newHarness(t, nil)
	token := open(t, h, "dev-admin")

	status, code, arrived := reached(h, control.Session(), request(t, "dev-analyst", token))
	if arrived {
		t.Error("a token was spent on another caller's connection")
	}
	if status != http.StatusUnauthorized || code != control.CodeWrongCertificate {
		t.Errorf("a borrowed token answered %d %q", status, code)
	}
}

func TestARevokedSessionStopsWorkingAtTheNextRequest(t *testing.T) {
	h := newHarness(t, nil)
	session, token, err := h.sessions.Open("dev-analyst", authz.Fingerprint(certificate("dev-analyst")), now)
	if err != nil {
		t.Fatalf("open a session: %v", err)
	}

	if _, _, arrived := reached(h, control.Session(), request(t, "dev-analyst", token)); !arrived {
		t.Fatal("a live session was refused")
	}
	if ended := h.sessions.Revoke(session.ID()); ended != 1 {
		t.Fatalf("revoking ended %d sessions", ended)
	}

	status, code, arrived := reached(h, control.Session(), request(t, "dev-analyst", token))
	if arrived {
		t.Error("a revoked session still reached a handler")
	}
	if status != http.StatusUnauthorized || code != control.CodeSessionRevoked {
		t.Errorf("a revoked session answered %d %q", status, code)
	}
}

// The token carries no authority, so taking a role away lands at the next
// request rather than at the next expiry.
func TestTakingARoleAwayLandsWithoutWaitingForTheToken(t *testing.T) {
	h := newHarness(t, nil)
	token := open(t, h, "dev-analyst")

	if _, _, arrived := reached(h, control.Permits(authz.Events, authz.Read), request(t, "dev-analyst", token)); !arrived {
		t.Fatal("the analyst was refused what the policy grants")
	}

	narrowed, err := authz.NewRole("analyst", "reads nothing much", []authz.Permission{{Resource: authz.Alerts, Action: authz.Read}})
	if err != nil {
		t.Fatalf("build a role: %v", err)
	}
	binding, err := authz.NewBinding("dev-analyst", []string{"analyst"}, []string{"default"})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	replacement, err := authz.Compile([]authz.Role{narrowed}, []authz.Binding{binding})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	h.registry.Replace(replacement)

	status, code, arrived := reached(h, control.Permits(authz.Events, authz.Read), request(t, "dev-analyst", token))
	if arrived {
		t.Error("the old grant survived the policy change")
	}
	if status != http.StatusForbidden || code != control.CodeForbidden {
		t.Errorf("the narrowed caller answered %d %q", status, code)
	}
}

func TestAnExpiredSessionIsRefusedAsExpired(t *testing.T) {
	h := newHarness(t, nil)
	key, err := authz.RandomSessionKey()
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	issuer, err := authz.NewIssuer(key, time.Minute)
	if err != nil {
		t.Fatalf("build an issuer: %v", err)
	}
	sessions, err := control.NewSessions(control.SessionOptions{Issuer: issuer})
	if err != nil {
		t.Fatalf("build a session store: %v", err)
	}
	_, token, err := sessions.Open("dev-analyst", authz.Fingerprint(certificate("dev-analyst")), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("open a session: %v", err)
	}

	guard, err := control.NewGuard(control.GuardOptions{
		Sessions: sessions,
		Registry: h.registry,
		Metrics:  h.metrics,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("build a guard: %v", err)
	}

	status, code, arrived := reached(&harness{guard: guard}, control.Session(), request(t, "dev-analyst", token))
	if arrived {
		t.Error("an expired session reached a handler")
	}
	if status != http.StatusUnauthorized || code != control.CodeSessionExpired {
		t.Errorf("an expired session answered %d %q", status, code)
	}
}

func TestAMalformedCredentialIsNotTreatedAsAbsent(t *testing.T) {
	h := newHarness(t, nil)

	for name, header := range map[string]string{
		"a bare token":    "not-a-scheme",
		"a wrong scheme":  "Basic abcdef",
		"an empty bearer": "Bearer ",
		"a forged bearer": "Bearer aaaa.bbbb",
	} {
		r := request(t, "dev-analyst", "")
		r.Header.Set("Authorization", header)

		status, _, arrived := reached(h, control.Certificate(), r)
		if arrived {
			t.Errorf("%s reached a certificate route as though no credential was offered", name)
		}
		if status != http.StatusUnauthorized {
			t.Errorf("%s answered %d", name, status)
		}
	}
}

func TestACallerSpendingMoreThanItsShareIsRefused(t *testing.T) {
	h := newHarness(t, ratelimit.NewLimiter(1, 2, 16))
	token := open(t, h, "dev-analyst")

	for attempt := range 2 {
		if _, _, arrived := reached(h, control.Session(), request(t, "dev-analyst", token)); !arrived {
			t.Fatalf("attempt %d inside the burst was refused", attempt)
		}
	}

	status, code, arrived := reached(h, control.Session(), request(t, "dev-analyst", token))
	if arrived {
		t.Error("a caller past its burst reached a handler")
	}
	if status != http.StatusTooManyRequests || code != control.CodeRateLimited {
		t.Errorf("a throttled caller answered %d %q", status, code)
	}
}

func TestAHandlerReachedOutsideTheGuardHoldsNothing(t *testing.T) {
	caller, known := control.CallerFrom(httptest.NewRequest(http.MethodGet, "/", nil).Context())
	if known {
		t.Fatal("a request that never met the guard carries a caller")
	}
	for _, resource := range authz.Resources() {
		for _, action := range authz.Actions() {
			if caller.Grant.Allows(authz.Permission{Resource: resource, Action: action}) {
				t.Errorf("the zero caller holds %s:%s", resource, action)
			}
		}
	}
}
