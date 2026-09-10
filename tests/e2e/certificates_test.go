package e2e_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func keyAndRequest(t *testing.T, agentID string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate an agent key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: agentID}}, key)
	if err != nil {
		t.Fatalf("create a certificate request: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func (c *controlPlane) agentClient(t *testing.T, key *ecdsa.PrivateKey, issued *agentv1.IssuedCertificate) *http.Client {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("encode the agent key: %v", err)
	}
	keypair, err := tls.X509KeyPair(
		append(append([]byte(nil), issued.GetCertificatePem()...), issued.GetChainPem()...),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatalf("load the agent keypair: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(issued.GetTrustBundlePem()) {
		t.Fatal("the bundle the agent was told to trust holds no authority")
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

func (c *controlPlane) renew(t *testing.T, client *http.Client, requestPEM []byte) (*http.Response, []byte) {
	t.Helper()

	payload, err := proto.Marshal(&agentv1.RenewalRequest{CsrPem: requestPEM})
	if err != nil {
		t.Fatalf("encode the renewal: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost,
		"https://"+c.renewalAddress+control.RenewalPath, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build the renewal request: %v", err)
	}
	request.Header.Set("Content-Type", control.ContentType)

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("call the renewal listener: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })

	answer, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the renewal answer: %v", err)
	}
	return response, answer
}

func (c *controlPlane) issue(t *testing.T, client *http.Client, token, agentID string, requestPEM []byte) *agentv1.IssuedCertificate {
	t.Helper()

	response, body := c.send(t, client, http.MethodPost, "/v1/agents/"+agentID+"/certificate", token,
		&agentv1.CertificateRequest{CsrPem: requestPEM, Note: "the machine was built"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("issuing was refused: %d %s", response.StatusCode, body)
	}
	var issued agentv1.IssuedCertificate
	decode(t, body, &issued)
	return &issued
}

func (c *controlPlane) register(t *testing.T, client *http.Client, token, agentID string) {
	t.Helper()

	response, body := c.send(t, client, http.MethodPost, control.AgentsPath, token,
		&agentv1.Registration{AgentId: agentID, TenantId: "default"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("registering was refused: %d %s", response.StatusCode, body)
	}
}

// The whole lifecycle the card asks for, over real mutual TLS: an operator has
// the platform sign the first certificate, the agent renews with the one it
// holds and nobody is involved, and what the platform stopped honouring stops
// being renewable.
func TestAnAgentIsIssuedACertificateAndThenRenewsItItself(t *testing.T) {
	plane := startControlAPI(t, nil)
	operator := plane.caller(t, "e2e-admin")
	token := plane.open(t, operator).GetToken()
	plane.register(t, operator, token, "e2e-agent-70")

	key, requestPEM := keyAndRequest(t, "e2e-agent-70")
	issued := plane.issue(t, operator, token, "e2e-agent-70", requestPEM)

	held, err := plane.agents.Agent(t.Context(), "e2e-agent-70", []string{"default"})
	if err != nil {
		t.Fatalf("read the agent back: %v", err)
	}
	if got, _ := agent.FromWire(held.GetState()); got != agent.Active {
		t.Fatalf("an agent holding an issued certificate is %s", got)
	}

	renewalKey, renewalRequest := keyAndRequest(t, "e2e-agent-70")
	response, body := plane.renew(t, plane.agentClient(t, key, issued), renewalRequest)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("renewing was refused: %d %s", response.StatusCode, body)
	}
	var renewed agentv1.IssuedCertificate
	decode(t, body, &renewed)
	if renewed.GetIdentity().GetFingerprintSha256() == issued.GetIdentity().GetFingerprintSha256() {
		t.Fatal("renewing returned the certificate it was replacing")
	}

	held, err = plane.agents.Agent(t.Context(), "e2e-agent-70", []string{"default"})
	if err != nil {
		t.Fatalf("read the agent back: %v", err)
	}
	if held.GetIdentity().GetFingerprintSha256() != renewed.GetIdentity().GetFingerprintSha256() {
		t.Fatal("the registry did not follow the certificate it just signed")
	}

	trail := plane.certificates(t, operator, token, "e2e-agent-70")
	if len(trail.GetCertificates()) != 2 {
		t.Fatalf("the trail holds %d certificates", len(trail.GetCertificates()))
	}
	if trail.GetCertificates()[0].GetIssuedBy() != "e2e-agent-70" {
		t.Fatalf("a self-renewal is attributed to %q", trail.GetCertificates()[0].GetIssuedBy())
	}
	if trail.GetCertificates()[1].GetIssuedBy() != "e2e-admin" {
		t.Fatalf("the first certificate is attributed to %q", trail.GetCertificates()[1].GetIssuedBy())
	}

	if response, body = plane.renew(t, plane.agentClient(t, renewalKey, &renewed), renewalRequest); response.StatusCode != http.StatusCreated {
		t.Fatalf("the renewed certificate could not renew again: %d %s", response.StatusCode, body)
	}
}

func TestARevokedAgentStopsBeingAbleToRenew(t *testing.T) {
	plane := startControlAPI(t, nil)
	operator := plane.caller(t, "e2e-admin")
	token := plane.open(t, operator).GetToken()
	plane.register(t, operator, token, "e2e-agent-71")

	key, requestPEM := keyAndRequest(t, "e2e-agent-71")
	issued := plane.issue(t, operator, token, "e2e-agent-71", requestPEM)
	client := plane.agentClient(t, key, issued)

	response, body := plane.send(t, operator, http.MethodPost, "/v1/agents/e2e-agent-71/transition", token,
		&agentv1.TransitionRequest{To: agent.Revoked.Wire(), Note: "the key was found in a public repository"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoking was refused: %d %s", response.StatusCode, body)
	}

	_, renewalRequest := keyAndRequest(t, "e2e-agent-71")
	if response, body = plane.renew(t, client, renewalRequest); response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a revoked agent renewed: %d %s", response.StatusCode, body)
	}
}

func (c *controlPlane) certificates(t *testing.T, client *http.Client, token, agentID string) *agentv1.CertificateHistory {
	t.Helper()

	response, body := c.send(t, client, http.MethodGet, "/v1/agents/"+agentID+"/certificates", token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reading the certificate trail was refused: %d %s", response.StatusCode, body)
	}
	var trail agentv1.CertificateHistory
	decode(t, body, &trail)
	return &trail
}

// The rotation the card asks for a testable path to. Adding the next authority
// to the bundle is one file write with no restart, both authorities are honoured
// while the estate moves, and dropping the previous one ends it — an agent that
// renewed inside the window is unaffected and one that did not is refused, which
// is why step two waits for the estate rather than for a clock.
func TestACertificateAuthorityIsRotatedWithoutStrandingAnAgent(t *testing.T) {
	plane := startControlAPI(t, nil)
	operator := plane.caller(t, "e2e-admin")
	token := plane.open(t, operator).GetToken()
	plane.register(t, operator, token, "e2e-agent-72")

	key, requestPEM := keyAndRequest(t, "e2e-agent-72")
	issued := plane.issue(t, operator, token, "e2e-agent-72", requestPEM)
	current := plane.agentClient(t, key, issued)

	next, err := devpki.NewAuthority("Seagull Next Agent Test CA", time.Hour)
	if err != nil {
		t.Fatalf("create the next authority: %v", err)
	}
	coexisting := append(append([]byte(nil), plane.agentAuthority.Material().CertificatePEM...),
		next.Material().CertificatePEM...)
	write(t, plane.bundleFile, coexisting)

	_, renewalRequest := keyAndRequest(t, "e2e-agent-72")
	response, body := plane.renew(t, current, renewalRequest)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("renewing during a rotation was refused: %d %s", response.StatusCode, body)
	}
	var renewed agentv1.IssuedCertificate
	decode(t, body, &renewed)
	if !bytes.Equal(renewed.GetTrustBundlePem(), coexisting) {
		t.Fatal("an agent that renewed during a rotation was not told about the next authority")
	}

	// What an agent signed by the next authority would present. It authenticates
	// while both are trusted, which is what makes the middle of a rotation safe.
	elsewhere, err := next.IssueClient("e2e-agent-72", time.Hour)
	if err != nil {
		t.Fatalf("issue a certificate from the next authority: %v", err)
	}
	moved := plane.clientWithKey(t, elsewhere, coexisting)
	if response, body = plane.renew(t, moved, renewalRequest); response.StatusCode != http.StatusCreated {
		t.Fatalf("a certificate from the next authority was refused mid-rotation: %d %s", response.StatusCode, body)
	}

	// Retiring an authority takes effect on the next handshake, so the connection
	// that is already up drains rather than breaking mid-request.
	write(t, plane.bundleFile, plane.agentAuthority.Material().CertificatePEM)
	retired := plane.clientWithKey(t, elsewhere, coexisting)
	if _, err := retired.Post("https://"+plane.renewalAddress+control.RenewalPath, control.ContentType, nil); err == nil {
		t.Fatal("a certificate from an authority the bundle no longer carries still authenticated")
	}
	if response, body = plane.renew(t, current, renewalRequest); response.StatusCode != http.StatusCreated {
		t.Fatalf("an agent that renewed inside the window was stranded by the rotation: %d %s", response.StatusCode, body)
	}
}

func (c *controlPlane) clientWithKey(t *testing.T, material devpki.Material, bundle []byte) *http.Client {
	t.Helper()

	keypair, err := tls.X509KeyPair(material.CertificatePEM, material.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("load the keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		t.Fatal("the bundle holds no authority")
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
