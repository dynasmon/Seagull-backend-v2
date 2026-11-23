package e2e_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

type held struct {
	keypair tls.Certificate
	leaf    *x509.Certificate
}

func (h held) fingerprint() string {
	digest := sha256.Sum256(h.leaf.Raw)
	return hex.EncodeToString(digest[:])
}

func issuedBy(t *testing.T, authority *devpki.Authority, agentID string) held {
	t.Helper()
	material, err := authority.IssueClient(agentID, time.Hour)
	if err != nil {
		t.Fatalf("issue a client certificate: %v", err)
	}
	keypair, err := tls.X509KeyPair(material.CertificatePEM, material.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(material.CertificatePEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return held{keypair: keypair, leaf: leaf}
}

type renewing struct {
	client  *http.Client
	current atomic.Pointer[tls.Certificate]
}

func renewingClient(t *testing.T, g *gateway, first held) *renewing {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(g.authority.Material().CertificatePEM)
	agent := &renewing{}
	agent.current.Store(&first.keypair)
	agent.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return agent.current.Load(), nil },
	}}}
	t.Cleanup(agent.client.CloseIdleConnections)
	return agent
}

func (r *renewing) renewInto(next held) {
	r.current.Store(&next.keypair)
	r.client.CloseIdleConnections()
}

func bindsTo(t *testing.T, g *gateway, agentID string, revision uint64, inForce held, replaced *held, replacedAt time.Time, learned time.Time) {
	t.Helper()
	record := &agentv1.Admission{AgentId: agentID, TenantId: "acme", State: agent.Active.Wire(), Revision: revision,
		FingerprintSha256: inForce.fingerprint(), IssuedAt: timestamppb.New(inForce.leaf.NotBefore)}
	if replaced != nil {
		record.ReplacedFingerprintSha256, record.ReplacedAt = replaced.fingerprint(), timestamppb.New(replacedAt)
	}
	if err := g.roster.Learn(record, learned); err != nil {
		t.Fatalf("tell the roster: %v", err)
	}
}

func refusedCode(t *testing.T, response *http.Response, body []byte) string {
	t.Helper()
	var refused ingestv1.Rejection
	if err := proto.Unmarshal(body, &refused); err != nil {
		t.Fatalf("decode a %d answer: %v", response.StatusCode, err)
	}
	return refused.GetCode()
}

func post(t *testing.T, client *http.Client, url string, message proto.Message) (*http.Response, []byte) {
	t.Helper()
	response, body, err := posting(client, url, message)
	if err != nil {
		t.Fatalf("post to %s: %v", url, err)
	}
	return response, body
}

func posting(client *http.Client, url string, message proto.Message) (*http.Response, []byte, error) {
	encoded, err := proto.Marshal(message)
	if err != nil {
		return nil, nil, err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Content-Type", ingest.ContentType)
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return response, body, err
}

// The agent renews while its gateway has not heard of the renewal: the new
// certificate is answered so the agent sends again, the batches it was sending
// on the old one go on being taken, nothing is refused for good, and every
// batch lands once the gateway hears.
func TestAnAgentRenewingWhileItsGatewayHasNotHeardLosesNothingAndIsNeverRefusedForGood(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	first := issuedBy(t, gateway.authority, "web-07")
	bindsTo(t, gateway, "web-07", 2, first, nil, time.Time{}, time.Time{})
	sender := renewingClient(t, gateway, first)

	var (
		mu        sync.Mutex
		answered  = map[int]int{}
		sent      []string
		failed    error
		stop      = make(chan struct{})
		stopped   = make(chan struct{})
		attempted atomic.Int64
	)
	go func() {
		defer close(stopped)
		for index := 0; ; index++ {
			select {
			case <-stop:
				return
			default:
			}
			id := fmt.Sprintf("e0000000-0000-4000-8000-%012d", 700+index)
			batch := fixtures.Batch(fmt.Sprintf("batch-renewing-%d", index), fixtures.SSHAuthentication{EventID: id, At: time.Now().Add(-time.Second)}.Event())
			for {
				response, _, err := posting(sender.client, gateway.url(), batch)
				attempted.Add(1)
				mu.Lock()
				if err != nil {
					failed = err
					mu.Unlock()
					return
				}
				answered[response.StatusCode]++
				mu.Unlock()
				if response.StatusCode == http.StatusOK {
					break
				}
				if response.StatusCode != http.StatusServiceUnavailable {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			mu.Lock()
			sent = append(sent, id)
			mu.Unlock()
		}
	}()

	waitFor(t, "batches on the first certificate", func() bool { return attempted.Load() >= 5 })
	second := issuedBy(t, gateway.authority, "web-07")
	sender.renewInto(second)
	waitFor(t, "the renewed certificate answered as unheard", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return answered[http.StatusServiceUnavailable] >= 3
	})
	bindsTo(t, gateway, "web-07", 3, second, &first, time.Now(), time.Now())
	before := attempted.Load()
	waitFor(t, "batches on the renewed certificate", func() bool { return attempted.Load() >= before+5 })
	close(stop)
	<-stopped

	mu.Lock()
	defer mu.Unlock()
	if failed != nil {
		t.Fatalf("a renewing agent could not reach its gateway: %v", failed)
	}
	for status, count := range answered {
		if status != http.StatusOK && status != http.StatusServiceUnavailable {
			t.Fatalf("a renewing agent was answered %d %d times: %v", status, count, answered)
		}
	}
	stored := map[string]bool{}
	for _, event := range gateway.backbone.published {
		stored[event.GetEventId()] = true
	}
	for _, id := range sent {
		if !stored[id] {
			t.Fatalf("event %s the gateway acknowledged is not on the backbone", id)
		}
	}
	if len(sent) < 10 {
		t.Fatalf("only %d batches were delivered across the renewal", len(sent))
	}
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("%s never happened", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The renewal lands while a batch sent on the old certificate is being made
// durable: the batch completes, and its connection is not used again.
func TestABatchInFlightWhenTheRenewalLandsCompletesAndItsConnectionCloses(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{})
	gateway := startGateway(t, gatewayOptions{backbone: &backbone{release: release, entered: entered}})
	first, second := issuedBy(t, gateway.authority, "web-08"), issuedBy(t, gateway.authority, "web-08")
	bindsTo(t, gateway, "web-08", 2, first, nil, time.Time{}, time.Time{})
	sender := renewingClient(t, gateway, first)

	type answer struct {
		response *http.Response
		body     []byte
	}
	done := make(chan answer, 1)
	go func() {
		response, body := post(t, sender.client, gateway.url(), fixtures.Batch("batch-in-flight",
			fixtures.SSHAuthentication{EventID: "e0000000-0000-4000-8000-000000000801", At: time.Now().Add(-time.Second)}.Event()))
		done <- answer{response, body}
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the batch never reached the backbone")
	}
	bindsTo(t, gateway, "web-08", 3, second, &first, time.Now(), time.Now())
	close(release)

	landed := <-done
	if landed.response.StatusCode != http.StatusOK || !landed.response.Close {
		t.Fatalf("the batch in flight was answered %d, the connection closing %t", landed.response.StatusCode, landed.response.Close)
	}
}

// The audit's sequence (INT-10): with the certificate a renewal had replaced,
// past the tolerance, a forged batch and a copy's inventory are refused and
// nothing reaches the backbone, while the installation that renewed is taken;
// what was refused reaches the judge as one record naming the certificate in
// force. Whether the copy or the original renewed first makes no difference
// here: the one that did not presents the replaced certificate.
func TestTheInstallationThatDidNotRenewDeliversNothing(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	shared, renewed := issuedBy(t, gateway.authority, "web-09"), issuedBy(t, gateway.authority, "web-09")
	bindsTo(t, gateway, "web-09", 3, renewed, &shared, time.Now().Add(-2*time.Minute), time.Time{})
	left := gateway.clientWith(t, devpki.Material{}, gateway.authority.Material().CertificatePEM)
	left.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{shared.keypair}
	ahead := gateway.clientWith(t, devpki.Material{}, gateway.authority.Material().CertificatePEM)
	ahead.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{renewed.keypair}

	forged := fixtures.Batch("batch-forged", fixtures.SSHAuthentication{EventID: "e0000000-0000-4000-8000-000000000901", At: time.Now().Add(-time.Second)}.Event())
	if response, body := post(t, left, gateway.url(), forged); response.StatusCode != http.StatusForbidden ||
		refusedCode(t, response, body) != ingest.CodeCertificateReplaced {
		t.Fatalf("a forged batch on the replaced certificate was answered %d", response.StatusCode)
	}
	scan := fixtures.InventoryBatch("batch-copy-inventory", fixtures.PackageScan{At: time.Now().Add(-time.Minute)}.Record())
	if response, body := post(t, left, gateway.inventoryURL(), scan); response.StatusCode != http.StatusForbidden ||
		refusedCode(t, response, body) != ingest.CodeCertificateReplaced {
		t.Fatalf("the copy's inventory was answered %d", response.StatusCode)
	}
	if len(gateway.backbone.published) != 0 || len(gateway.backbone.inventory) != 0 {
		t.Fatalf("the backbone holds %d events and %d inventory records from a replaced certificate",
			len(gateway.backbone.published), len(gateway.backbone.inventory))
	}

	if response, _ := post(t, ahead, gateway.url(), forged); response.StatusCode != http.StatusOK {
		t.Fatalf("the installation that renewed was answered %d", response.StatusCode)
	}
	if err := gateway.refused.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	heard := gateway.refusals.heard()
	if len(heard) != 1 || heard[0].GetAgentId() != "web-09" || heard[0].GetRefusals() != 2 ||
		heard[0].GetFingerprintSha256() != renewed.fingerprint() || heard[0].GetRevision() != 3 {
		t.Fatalf("the refusals reached the judge as %v", heard)
	}
}

// While two authorities are trusted during a rotation, the certificate in force
// is admitted whichever signed it, and the one it replaced is refused whichever
// signed that.
func TestTheCertificateInForceDecidesWhileTwoAuthoritiesAreTrusted(t *testing.T) {
	next, err := devpki.NewAuthority("Seagull Next Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gateway := startGateway(t, gatewayOptions{alsoTrust: next})
	before, after := issuedBy(t, gateway.authority, "web-10"), issuedBy(t, next, "web-10")
	bindsTo(t, gateway, "web-10", 3, after, &before, time.Now().Add(-2*time.Minute), time.Time{})

	presenting := func(certificate held) *http.Client {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(gateway.authority.Material().CertificatePEM)
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate.keypair}}}}
		t.Cleanup(client.CloseIdleConnections)
		return client
	}
	batch := fixtures.Batch("batch-rotation", fixtures.SSHAuthentication{EventID: "e0000000-0000-4000-8000-000000001001", At: time.Now().Add(-time.Second)}.Event())
	if response, _ := post(t, presenting(after), gateway.url(), batch); response.StatusCode != http.StatusOK {
		t.Fatalf("the certificate in force, signed by the next authority, was answered %d", response.StatusCode)
	}
	if response, body := post(t, presenting(before), gateway.url(), batch); response.StatusCode != http.StatusForbidden ||
		refusedCode(t, response, body) != ingest.CodeCertificateReplaced {
		t.Fatalf("the certificate it replaced, signed by the authority before, was answered %d", response.StatusCode)
	}
}
