package control_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func signingRequest(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatalf("create a certificate request: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestIssuingACertificateBindsItAndMakesAPendingAgentActive(t *testing.T) {
	h := newHarness(t, nil)
	held := newStubAgents()
	handler := registry(t, h, held, &stubAdmissions{})
	operator := session(t, handler, "dev-admin")

	response := call(t, handler, http.MethodPost, "/v1/agents/web-01/certificate", "dev-admin", operator,
		&agentv1.CertificateRequest{CsrPem: signingRequest(t, "web-01")})
	if response.Code != http.StatusCreated {
		t.Fatalf("issuing a certificate answered %d: %s", response.Code, response.Body)
	}

	var issued agentv1.IssuedCertificate
	if err := proto.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatalf("read what was issued: %v", err)
	}
	if len(issued.GetCertificatePem()) == 0 || len(issued.GetChainPem()) == 0 || len(issued.GetTrustBundlePem()) == 0 {
		t.Fatal("an issued certificate came back without its chain or the bundle to trust")
	}
	if held.held["web-01"].GetState() != agentv1.State_STATE_ACTIVE {
		t.Fatalf("the agent is %s after being issued a certificate", held.held["web-01"].GetState())
	}
	if bound := held.held["web-01"].GetIdentity().GetFingerprintSha256(); bound != issued.GetIdentity().GetFingerprintSha256() {
		t.Fatalf("the registry bound %q and the authority signed %q", bound, issued.GetIdentity().GetFingerprintSha256())
	}
}

func TestACertificateRequestNamingAnotherAgentIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	handler := registry(t, h, newStubAgents(), &stubAdmissions{})
	operator := session(t, handler, "dev-admin")

	response := call(t, handler, http.MethodPost, "/v1/agents/web-01/certificate", "dev-admin", operator,
		&agentv1.CertificateRequest{CsrPem: signingRequest(t, "web-99")})
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a request naming another agent answered %d: %s", response.Code, response.Body)
	}
}

func TestIssuingACertificateNeedsMoreThanReadingAnAgent(t *testing.T) {
	h := newHarness(t, nil)
	handler := registry(t, h, newStubAgents(), &stubAdmissions{})
	analyst := session(t, handler, "dev-analyst")

	response := call(t, handler, http.MethodPost, "/v1/agents/web-01/certificate", "dev-analyst", analyst,
		&agentv1.CertificateRequest{CsrPem: signingRequest(t, "web-01")})
	if response.Code != http.StatusForbidden {
		t.Fatalf("an analyst issued a certificate: %d %s", response.Code, response.Body)
	}
}

func TestTheCertificateTrailKeepsWhatTheNextCertificateReplaced(t *testing.T) {
	h := newHarness(t, nil)
	handler := registry(t, h, newStubAgents(), &stubAdmissions{})
	operator := session(t, handler, "dev-admin")

	for range 2 {
		response := call(t, handler, http.MethodPost, "/v1/agents/web-01/certificate", "dev-admin", operator,
			&agentv1.CertificateRequest{CsrPem: signingRequest(t, "web-01")})
		if response.Code != http.StatusCreated {
			t.Fatalf("issuing a certificate answered %d: %s", response.Code, response.Body)
		}
	}

	response := call(t, handler, http.MethodGet, "/v1/agents/web-01/certificates", "dev-admin", operator, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("reading the certificate trail answered %d: %s", response.Code, response.Body)
	}

	var trail agentv1.CertificateHistory
	if err := proto.Unmarshal(response.Body.Bytes(), &trail); err != nil {
		t.Fatalf("read the certificate trail: %v", err)
	}
	if len(trail.GetCertificates()) != 2 {
		t.Fatalf("two certificates were issued and the trail holds %d", len(trail.GetCertificates()))
	}
	if got := trail.GetCertificates()[0].GetAuthoritySubject(); got != authoritySubject {
		t.Fatalf("the trail names the authority %q", got)
	}
	if got := trail.GetCertificates()[0].GetIssuedBy(); got != "dev-admin" {
		t.Fatalf("the trail says %q asked for it", got)
	}
}

// A listener signing with an authority nothing it publishes trusts sends every
// agent that renews onto a certificate it cannot verify the platform with.
func TestAListenerRefusesToServeOnABundleThatDoesNotTrustItsAuthority(t *testing.T) {
	h := newHarness(t, nil)
	signing, _ := testAuthority(t)
	_, elsewhere := testAuthority(t)

	_, err := control.NewHandler(control.ServerOptions{
		Guard: h.guard, Sessions: h.sessions, Registry: h.registry,
		Rulesets: newStubRulesets(), Alerts: newStubAlerts(), Incidents: newStubIncidents(),
		Agents: newStubAgents(), Admissions: &stubAdmissions{},
		Authority: signing, TrustBundle: elsewhere, CertificateLife: time.Hour,
		Metrics: h.metrics, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-bundle")),
	})
	if err == nil {
		t.Fatal("a listener served with a bundle that does not trust the authority it signs with")
	}
}
