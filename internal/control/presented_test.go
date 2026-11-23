package control_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var listenerClock = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

type presentedLeaf struct {
	raw       string
	notBefore time.Time
}

var (
	firstLeaf  = presentedLeaf{raw: "the first certificate of web-01", notBefore: listenerClock.Add(-48 * time.Hour)}
	secondLeaf = presentedLeaf{raw: "the certificate web-01 renewed into", notBefore: listenerClock.Add(-time.Hour)}
)

func (l presentedLeaf) fingerprint() string {
	digest := sha256.Sum256([]byte(l.raw))
	return hex.EncodeToString(digest[:])
}

func (l presentedLeaf) identity() *agentv1.Identity {
	return &agentv1.Identity{Subject: "web-01", Serial: "0a1b2c", FingerprintSha256: l.fingerprint(),
		IssuedAt: timestamppb.New(l.notBefore), ExpiresAt: timestamppb.New(listenerClock.Add(100 * time.Hour))}
}

// web-01 is bound to the first certificate and renewed into the second at
// renewedAt, presenting the first.
func renewedAgent(t *testing.T, renewedAt time.Time) *stubAgents {
	t.Helper()
	held := newStubAgents()
	if _, err := held.Move(t.Context(), "web-01", []string{"default"}, agent.Move{Identity: firstLeaf.identity(), Actor: "dev-admin",
		At: listenerClock.Add(-48 * time.Hour)}); err != nil {
		t.Fatalf("bind the first certificate: %v", err)
	}
	if _, err := held.Renew(t.Context(), "web-01", agent.Move{Identity: secondLeaf.identity(), Actor: "web-01", At: renewedAt,
		PresentedFingerprint: firstLeaf.fingerprint()}); err != nil {
		t.Fatalf("renew: %v", err)
	}
	return held
}

func agentListening(t *testing.T, held *stubAgents) (http.Handler, *metrics.Registry) {
	t.Helper()
	signing, bundle := testAuthority(t)
	registry := metrics.New("control-api-presented")
	handler, err := control.NewRenewalHandler(control.ServerOptions{
		Agents: held, Policies: newStubPolicies(held), Authority: signing, TrustBundle: bundle, CertificateLife: time.Hour,
		ReplacedTolerance: time.Minute, Now: func() time.Time { return listenerClock },
		Metrics: control.NewMetrics(registry), Logger: slog.New(slog.DiscardHandler),
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-presented-routes")),
	})
	if err != nil {
		t.Fatalf("build the agent listener: %v", err)
	}
	return handler, registry
}

func presenting(t *testing.T, handler http.Handler, method, path string, leaf presentedLeaf) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, &bytes.Buffer{})
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{
		Raw: []byte(leaf.raw), NotBefore: leaf.notBefore, Subject: pkix.Name{CommonName: "web-01"},
	}}}}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

var agentListenerRoutes = []struct{ method, path, route string }{
	{http.MethodGet, control.PolicyPath, http.MethodGet + " " + control.PolicyPath},
	{http.MethodGet, control.UpdatePath, http.MethodGet + " " + control.UpdatePath},
	{http.MethodGet, strings.Replace(control.UpdatePackagePath, "{sha256}", strings.Repeat("ab", 32), 1),
		http.MethodGet + " " + control.UpdatePackagePath},
	{http.MethodGet, control.DescriptorPath, http.MethodGet + " " + control.DescriptorPath},
}

func TestTheAgentListenerRefusesACertificateARenewalReplacedOnceTheToleranceHasPassed(t *testing.T) {
	held := renewedAgent(t, listenerClock.Add(-10*time.Minute))
	handler, registry := agentListening(t, held)

	for _, route := range agentListenerRoutes {
		answered := presenting(t, handler, route.method, route.path, firstLeaf)
		refusedWith(t, answered, http.StatusForbidden, control.CodeCertificateReplaced)
		if answered.Header().Get("Connection") != "close" {
			t.Errorf("%s with the replaced certificate kept its connection open", route.route)
		}
	}

	if len(held.used) != len(agentListenerRoutes) {
		t.Fatalf("%d refusals were recorded, and %d were answered", len(held.used), len(agentListenerRoutes))
	}
	for index, used := range held.used {
		if used.agentID != "web-01" || used.inForce != secondLeaf.fingerprint() || used.route != agentListenerRoutes[index].route ||
			!used.at.Equal(listenerClock) {
			t.Errorf("refusal %d was recorded as %+v", index, used)
		}
	}
	if refused := gauged(t, registry, `seagull_control_agent_certificates_total{standing="replaced"}`); refused != float64(len(agentListenerRoutes)) {
		t.Errorf("%v refusals of a replaced certificate were counted", refused)
	}
}

func TestTheAgentListenerServesTheReplacedCertificateForTheToleranceAndClosesItsConnection(t *testing.T) {
	held := renewedAgent(t, listenerClock.Add(-30*time.Second))
	handler, _ := agentListening(t, held)

	answered := presenting(t, handler, http.MethodGet, control.DescriptorPath, firstLeaf)
	if answered.Code != http.StatusOK || answered.Header().Get("Connection") != "close" {
		t.Fatalf("the replaced certificate inside the tolerance was answered %d, connection %q: %s",
			answered.Code, answered.Header().Get("Connection"), answered.Body)
	}
	if len(held.used) != 0 {
		t.Fatalf("a certificate inside the tolerance was recorded as refused: %+v", held.used)
	}
}

func TestTheAgentListenerServesTheCertificateInForceAsBefore(t *testing.T) {
	held := renewedAgent(t, listenerClock.Add(-10*time.Minute))
	handler, _ := agentListening(t, held)

	refusedWith(t, presenting(t, handler, http.MethodGet, control.PolicyPath, secondLeaf), http.StatusNotFound, control.CodeNoPolicy)
	answered := presenting(t, handler, http.MethodGet, control.DescriptorPath, secondLeaf)
	if answered.Code != http.StatusOK || answered.Header().Get("Connection") != "" {
		t.Fatalf("the certificate in force was answered %d, connection %q", answered.Code, answered.Header().Get("Connection"))
	}
}

func TestAnAgentTheRegistryNoLongerAdmitsIsToldSoWhateverCertificateItPresents(t *testing.T) {
	held := renewedAgent(t, listenerClock.Add(-10*time.Minute))
	if _, err := held.Move(t.Context(), "web-01", []string{"default"}, agent.Move{To: agent.Disabled, Note: "copied", Actor: "dev-admin",
		At: listenerClock.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	handler, _ := agentListening(t, held)

	refusedWith(t, presenting(t, handler, http.MethodGet, control.PolicyPath, firstLeaf), http.StatusForbidden, control.CodeNotAdmitted)
	if len(held.used) != 0 {
		t.Fatalf("an agent no longer admitted was recorded as using a replaced certificate: %+v", held.used)
	}
}
