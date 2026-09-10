package control_test

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func renewals(t *testing.T, held *stubAgents, limiter *ratelimit.Limiter) http.Handler {
	t.Helper()

	signing, bundle := testAuthority(t)
	handler, err := control.NewRenewalHandler(control.ServerOptions{
		Agents:          held,
		Authority:       signing,
		TrustBundle:     bundle,
		CertificateLife: 24 * time.Hour,
		RenewalLimiter:  limiter,
		Metrics:         control.NewMetrics(metrics.New("control-api-renewal-test")),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-renewal-routes")),
	})
	if err != nil {
		t.Fatalf("build the renewal listener: %v", err)
	}
	return handler
}

func active(t *testing.T, held *stubAgents, id string) {
	t.Helper()
	signing, _ := testAuthority(t)
	at := time.Now().UTC()
	issued, err := signing.Sign(id, signingRequest(t, id), time.Hour, at)
	if err != nil {
		t.Fatalf("sign a first certificate: %v", err)
	}
	if _, err := held.Move(t.Context(), id, []string{"default"}, agent.Move{
		Identity: issued.Identity, Actor: "dev-admin", At: at, Authority: authoritySubject,
	}); err != nil {
		t.Fatalf("bind a first certificate: %v", err)
	}
}

func TestAnAgentRenewsWithTheCertificateItIsReplacing(t *testing.T) {
	held := newStubAgents()
	active(t, held, "web-01")
	before := held.held["web-01"].GetIdentity().GetFingerprintSha256()

	response := call(t, renewals(t, held, nil), http.MethodPost, control.RenewalPath, "web-01", "",
		&agentv1.RenewalRequest{CsrPem: signingRequest(t, "web-01")})
	if response.Code != http.StatusCreated {
		t.Fatalf("renewing answered %d: %s", response.Code, response.Body)
	}

	var issued agentv1.IssuedCertificate
	if err := proto.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatalf("read what was issued: %v", err)
	}
	if issued.GetIdentity().GetFingerprintSha256() == before {
		t.Fatal("renewing returned the certificate it was replacing")
	}
	if bound := held.held["web-01"].GetIdentity().GetFingerprintSha256(); bound != issued.GetIdentity().GetFingerprintSha256() {
		t.Fatalf("the registry holds %q and the agent was given %q", bound, issued.GetIdentity().GetFingerprintSha256())
	}
	if held.held["web-01"].GetState() != agentv1.State_STATE_ACTIVE {
		t.Fatalf("renewing left the agent %s", held.held["web-01"].GetState())
	}
}

// The subject comes off the verified chain, so an agent cannot rename itself into
// somebody else's identity by asking for a certificate in their name.
func TestARenewalSignsTheAgentTheConnectionProved(t *testing.T) {
	held := newStubAgents()
	active(t, held, "web-01")

	response := call(t, renewals(t, held, nil), http.MethodPost, control.RenewalPath, "web-01", "",
		&agentv1.RenewalRequest{CsrPem: signingRequest(t, "db-07")})
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a renewal naming another agent answered %d: %s", response.Code, response.Body)
	}
}

func TestARenewalWithoutACertificateIsRefused(t *testing.T) {
	held := newStubAgents()
	response := call(t, renewals(t, held, nil), http.MethodPost, control.RenewalPath, "", "",
		&agentv1.RenewalRequest{CsrPem: signingRequest(t, "web-01")})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("an unidentified renewal answered %d: %s", response.Code, response.Body)
	}
}

func TestAnAgentThePlatformStoppedListeningToDoesNotRenew(t *testing.T) {
	for name, to := range map[string]agent.State{
		"disabled": agent.Disabled,
		"revoked":  agent.Revoked,
	} {
		t.Run(name, func(t *testing.T) {
			held := newStubAgents()
			active(t, held, "web-01")
			if _, err := held.Move(t.Context(), "web-01", []string{"default"}, agent.Move{
				To: to, Note: "the machine was retired", Actor: "dev-admin", At: held.clock,
			}); err != nil {
				t.Fatalf("move the agent to %s: %v", to, err)
			}

			response := call(t, renewals(t, held, nil), http.MethodPost, control.RenewalPath, "web-01", "",
				&agentv1.RenewalRequest{CsrPem: signingRequest(t, "web-01")})
			if response.Code != http.StatusUnprocessableEntity {
				t.Fatalf("a %s agent renewing answered %d: %s", to, response.Code, response.Body)
			}
		})
	}
}

func TestTheRenewalListenerServesNothingElse(t *testing.T) {
	held := newStubAgents()
	handler := renewals(t, held, nil)

	for _, path := range []string{control.AgentsPath, control.SessionPath, control.DescriptorPath} {
		if response := call(t, handler, http.MethodGet, path, "web-01", "", nil); response.Code != http.StatusNotFound {
			t.Fatalf("the renewal listener answered %s with %d", path, response.Code)
		}
	}
}

func TestAnAgentRenewingTooOftenIsSlowedDown(t *testing.T) {
	held := newStubAgents()
	active(t, held, "web-01")
	handler := renewals(t, held, ratelimit.NewLimiter(0.001, 1, 16))

	first := call(t, handler, http.MethodPost, control.RenewalPath, "web-01", "",
		&agentv1.RenewalRequest{CsrPem: signingRequest(t, "web-01")})
	if first.Code != http.StatusCreated {
		t.Fatalf("the first renewal answered %d: %s", first.Code, first.Body)
	}

	second := call(t, handler, http.MethodPost, control.RenewalPath, "web-01", "",
		&agentv1.RenewalRequest{CsrPem: signingRequest(t, "web-01")})
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("a second renewal answered %d: %s", second.Code, second.Body)
	}
}
