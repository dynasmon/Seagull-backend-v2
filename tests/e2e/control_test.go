package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/tlsx"
	"github.com/dynasmon/Seagull-backend-v2/internal/policyfile"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

const controlPolicy = `
schema_version: 1

roles:
  - name: analyst
    description: reads what the platform stored
    permissions:
      - events:read
      - detections:read

  - name: administrator
    description: administers the platform
    permissions:
      - events:read
      - rulesets:write
      - sessions:read
      - sessions:delete

bindings:
  - subject: e2e-analyst
    roles: [analyst]
    tenants: [default]

  - subject: e2e-admin
    roles: [administrator]
    tenants: [default]
`

type controlPlane struct {
	address   string
	authority *devpki.Authority
	sessions  *control.Sessions
	stopped   chan error
}

func startControlAPI(t *testing.T, limiter *ratelimit.Limiter) *controlPlane {
	t.Helper()

	authority, err := devpki.NewAuthority("Seagull Control Test CA", time.Hour)
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	server, err := authority.IssueServer("control-api", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("issue server certificate: %v", err)
	}

	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "control.pem")
	keyFile := filepath.Join(directory, "control-key.pem")
	authorityFile := filepath.Join(directory, "caller-ca.pem")
	write(t, certificateFile, server.CertificatePEM)
	write(t, keyFile, server.PrivateKeyPEM)
	write(t, authorityFile, authority.Material().CertificatePEM)

	material, err := tlsx.NewMaterial(certificateFile, keyFile, authorityFile)
	if err != nil {
		t.Fatalf("load tls material: %v", err)
	}
	mutual, err := material.MutualServerConfig()
	if err != nil {
		t.Fatalf("build mutual tls: %v", err)
	}

	platform, err := service.New(service.Config{
		Name:             "control-api",
		LogLevel:         "error",
		LogFormat:        "json",
		OpsAddress:       "127.0.0.1:0",
		ShutdownTimeout:  5 * time.Second,
		ReadinessTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("build service: %v", err)
	}

	policy, err := policyfile.Read("policy.yml", []byte(controlPolicy))
	if err != nil {
		t.Fatalf("read the policy: %v", err)
	}

	instruments := control.NewMetrics(platform.Metrics())
	registry, err := control.NewRegistry(control.RegistryOptions{
		Source:  control.SourceFunc(func() (*authz.Policy, error) { return policy, nil }),
		Metrics: instruments,
		Logger:  platform.Logger(),
	})
	if err != nil {
		t.Fatalf("build the registry: %v", err)
	}

	issuer, err := authz.NewIssuer(bytes.Repeat([]byte("s"), 32), 15*time.Minute)
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
		Logger:   platform.Logger(),
	})
	if err != nil {
		t.Fatalf("build a guard: %v", err)
	}

	listener, err := control.NewServer(control.ServerOptions{
		Address:         "127.0.0.1:0",
		TLS:             mutual,
		Guard:           guard,
		Sessions:        sessions,
		Registry:        registry,
		Metrics:         instruments,
		Instrumentation: platform.HTTP(),
		Logger:          platform.Logger(),
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    10 * time.Second,
		IdleTimeout:     30 * time.Second,
		ShutdownTimeout: platform.ShutdownTimeout(),
	})
	if err != nil {
		t.Fatalf("build listener: %v", err)
	}
	platform.Add(listener)

	ctx, cancel := context.WithCancel(context.Background())
	running := &controlPlane{
		address:   listener.Address(),
		authority: authority,
		sessions:  sessions,
		stopped:   make(chan error, 1),
	}
	go func() { running.stopped <- platform.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-running.stopped:
			if err != nil {
				t.Errorf("the control plane stopped with an error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("the control plane did not stop")
		}
	})
	return running
}

func (c *controlPlane) caller(t *testing.T, name string) *http.Client {
	t.Helper()

	material, err := c.authority.IssueCaller(name, []string{"default"}, time.Hour)
	if err != nil {
		t.Fatalf("issue caller certificate: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.authority.Material().CertificatePEM) {
		t.Fatal("the test authority certificate is unusable")
	}
	keypair, err := tls.X509KeyPair(material.CertificatePEM, material.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("load the caller keypair: %v", err)
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{keypair},
	}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func (c *controlPlane) send(t *testing.T, client *http.Client, method, path, token string, body proto.Message) (*http.Response, []byte) {
	t.Helper()

	var payload []byte
	if body != nil {
		encoded, err := proto.Marshal(body)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		payload = encoded
	}

	request, err := http.NewRequest(method, "https://"+c.address+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	request.Header.Set("Content-Type", control.ContentType)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("call the control plane: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })

	answer, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	return response, answer
}

func (c *controlPlane) open(t *testing.T, client *http.Client) *controlv1.SessionResponse {
	t.Helper()

	response, body := c.send(t, client, http.MethodPost, control.SessionPath, "", &controlv1.SessionRequest{})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("opening a session answered %d: %s", response.StatusCode, body)
	}

	var opened controlv1.SessionResponse
	if err := proto.Unmarshal(body, &opened); err != nil {
		t.Fatalf("decode the session: %v", err)
	}
	return &opened
}

func refusalCode(t *testing.T, body []byte) string {
	t.Helper()
	var refusal controlv1.Refusal
	if err := proto.Unmarshal(body, &refusal); err != nil {
		return ""
	}
	return refusal.GetCode()
}

func TestACallerSignsInOverMutualTLSAndIsToldWhatTheyHold(t *testing.T) {
	plane := startControlAPI(t, nil)
	analyst := plane.caller(t, "e2e-analyst")

	opened := plane.open(t, analyst)
	if opened.GetToken() == "" {
		t.Fatal("no token was issued")
	}
	if opened.GetSession().GetGrant().GetSubject() != "e2e-analyst" {
		t.Errorf("the grant names %q", opened.GetSession().GetGrant().GetSubject())
	}

	response, body := plane.send(t, analyst, http.MethodGet, control.SessionPath, opened.GetToken(), nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("describing the session answered %d: %s", response.StatusCode, body)
	}

	var described controlv1.Session
	if err := proto.Unmarshal(body, &described); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if described.GetId() != opened.GetSession().GetId() {
		t.Errorf("the session came back as %q", described.GetId())
	}
}

func TestAnUnknownCallerReachesNothingOverRealTLS(t *testing.T) {
	plane := startControlAPI(t, nil)
	stranger := plane.caller(t, "e2e-stranger")

	response, body := plane.send(t, stranger, http.MethodPost, control.SessionPath, "", &controlv1.SessionRequest{})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("an unbound caller answered %d: %s", response.StatusCode, body)
	}
	if code := refusalCode(t, body); code != control.CodeNoGrant {
		t.Errorf("an unbound caller was refused with %q", code)
	}
}

func TestATokenIsNotSpendableOnAnotherCallersConnection(t *testing.T) {
	plane := startControlAPI(t, nil)

	admin := plane.caller(t, "e2e-admin")
	analyst := plane.caller(t, "e2e-analyst")
	stolen := plane.open(t, admin).GetToken()

	response, body := plane.send(t, analyst, http.MethodGet, control.SessionPath, stolen, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a borrowed token answered %d: %s", response.StatusCode, body)
	}
	if code := refusalCode(t, body); code != control.CodeWrongCertificate {
		t.Errorf("a borrowed token was refused with %q", code)
	}
}

func TestAnAdministratorEndsAnAnalystsSessionOverRealTLS(t *testing.T) {
	plane := startControlAPI(t, nil)

	analyst := plane.caller(t, "e2e-analyst")
	admin := plane.caller(t, "e2e-admin")

	analystSession := plane.open(t, analyst)
	adminSession := plane.open(t, admin)

	refused, body := plane.send(t, analyst, http.MethodDelete, control.SessionPath, analystSession.GetToken(),
		&controlv1.RevocationRequest{SessionId: adminSession.GetSession().GetId()})
	if refused.StatusCode != http.StatusForbidden {
		t.Fatalf("the analyst ended an administrator's session: %d %s", refused.StatusCode, body)
	}

	ended, body := plane.send(t, admin, http.MethodDelete, control.SessionPath, adminSession.GetToken(),
		&controlv1.RevocationRequest{SessionId: analystSession.GetSession().GetId()})
	if ended.StatusCode != http.StatusOK {
		t.Fatalf("the administrator was refused: %d %s", ended.StatusCode, body)
	}

	gone, body := plane.send(t, analyst, http.MethodGet, control.SessionPath, analystSession.GetToken(), nil)
	if gone.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the ended session still answered %d", gone.StatusCode)
	}
	if code := refusalCode(t, body); code != control.CodeSessionRevoked {
		t.Errorf("the ended session was refused with %q", code)
	}
}

func TestACallerSpendingMoreThanItsShareIsRefusedOverRealTLS(t *testing.T) {
	plane := startControlAPI(t, ratelimit.NewLimiter(1, 3, 16))
	analyst := plane.caller(t, "e2e-analyst")

	opened := plane.open(t, analyst)
	for range 2 {
		plane.send(t, analyst, http.MethodGet, control.SessionPath, opened.GetToken(), nil)
	}

	response, body := plane.send(t, analyst, http.MethodGet, control.SessionPath, opened.GetToken(), nil)
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a caller past its burst answered %d", response.StatusCode)
	}
	if code := refusalCode(t, body); code != control.CodeRateLimited {
		t.Errorf("a throttled caller was refused with %q", code)
	}
}
