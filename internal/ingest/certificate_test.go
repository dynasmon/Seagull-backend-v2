package ingest_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

var gateClock = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

type leaf struct {
	raw       string
	notBefore time.Time
}

var (
	inForceLeaf  = leaf{raw: "the certificate in force", notBefore: gateClock.Add(-2 * time.Hour)}
	replacedLeaf = leaf{raw: "the certificate it replaced", notBefore: gateClock.Add(-50 * time.Hour)}
	newerLeaf    = leaf{raw: "a certificate issued after it", notBefore: gateClock.Add(-time.Minute)}
	olderLeaf    = leaf{raw: "a certificate replaced long ago", notBefore: gateClock.Add(-100 * time.Hour)}
)

func (l leaf) fingerprint() string {
	digest := sha256.Sum256([]byte(l.raw))
	return hex.EncodeToString(digest[:])
}

func (l leaf) presentedBy(agentID string) *tls.ConnectionState {
	certificate := &x509.Certificate{Raw: []byte(l.raw), NotBefore: l.notBefore, Subject: pkix.Name{CommonName: agentID}}
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
}

func renewedAt(replacedAt, learned time.Time) agentidentity.Held {
	return agentidentity.Held{
		Binding: agentidentity.Binding{
			Fingerprint: inForceLeaf.fingerprint(), IssuedAt: inForceLeaf.notBefore,
			Replaced: replacedLeaf.fingerprint(), ReplacedAt: replacedAt,
		},
		Revision: 7,
		Learned:  learned,
	}
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(by)
}

type refusalsSent struct {
	mu      sync.Mutex
	records []*agentv1.Refusal
	refuse  error
}

func (r *refusalsSent) PublishRefusals(ctx context.Context, refused []*agentv1.Refusal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refuse != nil {
		failure := r.refuse
		r.refuse = nil
		return failure
	}
	r.records = append(r.records, refused...)
	return nil
}

func (r *refusalsSent) sent() []*agentv1.Refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*agentv1.Refusal(nil), r.records...)
}

type gate struct {
	routes   http.Handler
	clock    *clock
	refusals *ingest.Refusals
	sent     *refusalsSent
	registry *metrics.Registry
	events   *hookedBackbone
}

type hookedBackbone struct {
	recordingBackbone
	during func()
}

func (h *hookedBackbone) PublishEvents(ctx context.Context, events []*eventv1.Event) error {
	if h.during != nil {
		h.during()
	}
	return h.recordingBackbone.PublishEvents(ctx, events)
}

func gated(t *testing.T, roster heldRoster, most int) *gate {
	t.Helper()
	opened := &gate{clock: &clock{now: gateClock}, sent: &refusalsSent{}, registry: metrics.New("gate"), events: &hookedBackbone{}}
	refusals, err := ingest.NewRefusals(ingest.RefusalsOptions{
		Gateway: "gateway-a", Publisher: opened.sent, Every: time.Second, Most: most,
		Registry: opened.registry, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	certificates, err := ingest.NewCertificates(ingest.CertificatesOptions{
		Tolerance: time.Minute, Refusals: refusals, Registry: opened.registry, Now: opened.clock.read,
	})
	if err != nil {
		t.Fatal(err)
	}
	opened.refusals = refusals
	opened.routes = routing(t, roster, nil, certificates, opened.events)
	return opened
}

func (g *gate) ask(t *testing.T, method, path string, state *tls.ConnectionState, body []byte) *http.Response {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", ingest.ContentType)
	request.TLS = state
	recorder := httptest.NewRecorder()
	g.routes.ServeHTTP(recorder, request)
	return recorder.Result()
}

func refusalIn(t *testing.T, answered *http.Response) *ingestv1.Rejection {
	t.Helper()
	body, err := io.ReadAll(answered.Body)
	if err != nil {
		t.Fatal(err)
	}
	var refused ingestv1.Rejection
	if err := proto.Unmarshal(body, &refused); err != nil {
		t.Fatalf("decode the refusal: %v", err)
	}
	return &refused
}

func freshEvents(t *testing.T) []byte {
	t.Helper()
	encoded, err := proto.Marshal(fixtures.Batch("batch-1", fixtures.SSHAuthentication{At: time.Now().Add(-time.Second)}.Event()))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func bindingRoster(held map[string]agentidentity.Held) heldRoster {
	roster := heldRoster{tenants: map[string]string{}, known: map[string]bool{}, bindings: held}
	for agentID := range held {
		roster.tenants[agentID], roster.known[agentID] = "acme", true
	}
	return roster
}

var gatewayRoutes = []struct{ method, path string }{
	{http.MethodPost, ingest.EventsPath},
	{http.MethodPost, ingest.InventoryPath},
	{http.MethodPost, ingest.StatusPath},
	{http.MethodPost, ingest.AssessmentsPath},
	{http.MethodGet, ingest.DescriptorPath},
}

func TestACertificateARenewalReplacedIsRefusedOnEveryRouteOnceTheToleranceHasPassed(t *testing.T) {
	opened := gated(t, bindingRoster(map[string]agentidentity.Held{"web-01": renewedAt(gateClock.Add(-10*time.Minute), time.Time{})}), 16)

	for _, route := range gatewayRoutes {
		for name, presented := range map[string]leaf{"the certificate it replaced": replacedLeaf, "an older one": olderLeaf} {
			answered := opened.ask(t, route.method, route.path, presented.presentedBy("web-01"), nil)
			if refused := refusalIn(t, answered); answered.StatusCode != http.StatusForbidden || refused.GetCode() != ingest.CodeCertificateReplaced {
				t.Errorf("%s %s with %s was answered %d %q", route.method, route.path, name, answered.StatusCode, refused.GetCode())
			}
			if answered.Header.Get("Connection") != "close" {
				t.Errorf("%s %s with %s kept the connection open", route.method, route.path, name)
			}
		}
	}
	if published := opened.events.last(); published != nil {
		t.Fatalf("a batch presented with a replaced certificate was published: %v", published)
	}
	if refused := counted(t, opened.registry, `seagull_ingest_certificates_total{standing="replaced"}`); refused != 10 {
		t.Fatalf("%v refusals of a replaced certificate were counted, and 10 were answered", refused)
	}
}

func TestTheCertificateARenewalReplacedIsAdmittedForTheToleranceAndItsConnectionClosed(t *testing.T) {
	learned := gateClock.Add(-30 * time.Second)
	opened := gated(t, bindingRoster(map[string]agentidentity.Held{"web-01": renewedAt(gateClock.Add(-10*time.Minute), learned)}), 16)

	answered := opened.ask(t, http.MethodPost, ingest.EventsPath, replacedLeaf.presentedBy("web-01"), freshEvents(t))
	if answered.StatusCode != http.StatusOK || answered.Header.Get("Connection") != "close" {
		t.Fatalf("a batch presented with the replaced certificate inside the tolerance was answered %d, connection %q",
			answered.StatusCode, answered.Header.Get("Connection"))
	}
	described := opened.ask(t, http.MethodGet, ingest.DescriptorPath, replacedLeaf.presentedBy("web-01"), nil)
	if described.StatusCode != http.StatusOK || described.Header.Get("Connection") != "close" {
		t.Fatalf("the descriptor asked with the replaced certificate inside the tolerance was answered %d, connection %q",
			described.StatusCode, described.Header.Get("Connection"))
	}

	opened.clock.advance(30 * time.Second)
	if answered := opened.ask(t, http.MethodGet, ingest.DescriptorPath, replacedLeaf.presentedBy("web-01"), nil); answered.StatusCode != http.StatusForbidden {
		t.Fatalf("the replaced certificate was answered %d once the tolerance from when the gateway learned it had passed", answered.StatusCode)
	}
}

func TestACertificateTheGatewayHasNotHeardOfIsAnsweredSoTheAgentTriesAgain(t *testing.T) {
	opened := gated(t, bindingRoster(map[string]agentidentity.Held{"web-01": renewedAt(gateClock.Add(-10*time.Minute), time.Time{})}), 16)

	for _, route := range gatewayRoutes {
		answered := opened.ask(t, route.method, route.path, newerLeaf.presentedBy("web-01"), freshEvents(t))
		refused := refusalIn(t, answered)
		if answered.StatusCode != http.StatusServiceUnavailable || refused.GetCode() != ingest.CodeRosterBehind ||
			answered.Header.Get("Retry-After") == "" || answered.Header.Get("Connection") != "close" {
			t.Errorf("%s %s with a certificate newer than the roster's was answered %d %q, retry after %q, connection %q",
				route.method, route.path, answered.StatusCode, refused.GetCode(), answered.Header.Get("Retry-After"), answered.Header.Get("Connection"))
		}
	}
	if published := opened.events.last(); published != nil {
		t.Fatalf("a batch presented with a certificate the roster had not heard of was published: %v", published)
	}
	if err := opened.refusals.Flush(context.Background()); err != nil || len(opened.sent.sent()) != 0 {
		t.Fatalf("a certificate the gateway had not heard of was reported as refused: %v %v", opened.sent.sent(), err)
	}
}

func TestTheCertificateInForceIsAdmittedAndItsConnectionKept(t *testing.T) {
	for name, held := range map[string]agentidentity.Held{
		"bound to it":             renewedAt(gateClock.Add(-10*time.Minute), time.Time{}),
		"bound to no certificate": {},
	} {
		t.Run(name, func(t *testing.T) {
			opened := gated(t, bindingRoster(map[string]agentidentity.Held{"web-01": held}), 16)
			answered := opened.ask(t, http.MethodPost, ingest.EventsPath, inForceLeaf.presentedBy("web-01"), freshEvents(t))
			if answered.StatusCode != http.StatusOK || answered.Header.Get("Connection") != "" {
				t.Fatalf("a batch presented with the certificate in force was answered %d, connection %q",
					answered.StatusCode, answered.Header.Get("Connection"))
			}
		})
	}
}

func TestARequestInFlightWhenTheRenewalLandsCompletesAndClosesItsConnection(t *testing.T) {
	roster := bindingRoster(map[string]agentidentity.Held{"web-01": {
		Binding:  agentidentity.Binding{Fingerprint: replacedLeaf.fingerprint(), IssuedAt: replacedLeaf.notBefore},
		Revision: 6,
	}})
	opened := gated(t, roster, 16)
	opened.events.during = func() { roster.bindings["web-01"] = renewedAt(gateClock, gateClock) }

	answered := opened.ask(t, http.MethodPost, ingest.EventsPath, replacedLeaf.presentedBy("web-01"), freshEvents(t))
	if answered.StatusCode != http.StatusOK || answered.Header.Get("Connection") != "close" {
		t.Fatalf("a batch in flight when the renewal landed was answered %d, connection %q",
			answered.StatusCode, answered.Header.Get("Connection"))
	}
	if published := opened.events.last(); len(published) != 1 {
		t.Fatalf("a batch in flight when the renewal landed published %d events", len(published))
	}
}

func TestTheRefusalsOfOneAgentAreGatheredIntoOneRecordNamingTheCertificateInForce(t *testing.T) {
	opened := gated(t, bindingRoster(map[string]agentidentity.Held{"web-01": renewedAt(gateClock.Add(-10*time.Minute), time.Time{})}), 16)

	opened.ask(t, http.MethodPost, ingest.EventsPath, replacedLeaf.presentedBy("web-01"), nil)
	opened.clock.advance(time.Second)
	opened.ask(t, http.MethodPost, ingest.StatusPath, olderLeaf.presentedBy("web-01"), nil)
	opened.clock.advance(time.Second)
	opened.ask(t, http.MethodGet, ingest.DescriptorPath, replacedLeaf.presentedBy("web-01"), nil)

	if err := opened.refusals.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	sent := opened.sent.sent()
	if len(sent) != 1 {
		t.Fatalf("three refusals of one agent became %d records", len(sent))
	}
	got := sent[0]
	if got.GetSchemaVersion() != 1 || got.GetReason() != agentv1.Refusal_REASON_REPLACED_CERTIFICATE ||
		got.GetTenantId() != "acme" || got.GetAgentId() != "web-01" || got.GetRevision() != 7 ||
		got.GetFingerprintSha256() != inForceLeaf.fingerprint() || got.GetGateway() != "gateway-a" || got.GetRefusals() != 3 ||
		got.GetUse().GetListener() != agentv1.Finding_Use_LISTENER_GATEWAY || got.GetUse().GetRoute() != ingest.DescriptorRoute ||
		!got.GetFirstRefusedAt().AsTime().Equal(gateClock) || !got.GetLastRefusedAt().AsTime().Equal(gateClock.Add(2*time.Second)) {
		t.Fatalf("the refusals were gathered as %v", got)
	}
	encoded, err := proto.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, presented := range []leaf{replacedLeaf, olderLeaf} {
		if bytes.Contains(encoded, []byte(presented.fingerprint())) {
			t.Fatalf("the refusal names the certificate that was presented: %v", got)
		}
	}
	if err := opened.refusals.Flush(context.Background()); err != nil || len(opened.sent.sent()) != 1 {
		t.Fatalf("refusals already published were published again: %v %v", opened.sent.sent(), err)
	}
}

func TestRefusalsTheBackboneDidNotTakeAreKeptForTheNextAttempt(t *testing.T) {
	opened := gated(t, bindingRoster(map[string]agentidentity.Held{"web-01": renewedAt(gateClock.Add(-10*time.Minute), time.Time{})}), 16)
	opened.sent.refuse = errors.New("the backbone is away")

	opened.ask(t, http.MethodPost, ingest.EventsPath, replacedLeaf.presentedBy("web-01"), nil)
	if err := opened.refusals.Flush(context.Background()); err == nil {
		t.Fatal("a flush the backbone refused reported success")
	}
	opened.clock.advance(time.Second)
	opened.ask(t, http.MethodPost, ingest.EventsPath, replacedLeaf.presentedBy("web-01"), nil)
	if err := opened.refusals.Flush(context.Background()); err != nil {
		t.Fatalf("flush again: %v", err)
	}

	sent := opened.sent.sent()
	if len(sent) != 1 || sent[0].GetRefusals() != 2 || !sent[0].GetFirstRefusedAt().AsTime().Equal(gateClock) {
		t.Fatalf("a refusal the backbone did not take was not carried by the next record: %v", sent)
	}
}

func TestRefusalsBeyondWhatTheGatewayHoldsAreCountedAndNotKept(t *testing.T) {
	opened := gated(t, bindingRoster(map[string]agentidentity.Held{
		"web-01": renewedAt(gateClock.Add(-10*time.Minute), time.Time{}),
		"web-02": renewedAt(gateClock.Add(-10*time.Minute), time.Time{}),
	}), 1)

	opened.ask(t, http.MethodPost, ingest.EventsPath, replacedLeaf.presentedBy("web-01"), nil)
	opened.ask(t, http.MethodPost, ingest.EventsPath, replacedLeaf.presentedBy("web-02"), nil)
	opened.ask(t, http.MethodPost, ingest.EventsPath, replacedLeaf.presentedBy("web-01"), nil)
	if err := opened.refusals.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	sent := opened.sent.sent()
	if len(sent) != 1 || sent[0].GetAgentId() != "web-01" || sent[0].GetRefusals() != 2 {
		t.Fatalf("a gateway holding one agent's refusals published %v", sent)
	}
	if dropped := counted(t, opened.registry, `seagull_ingest_refusals_total{outcome="dropped"}`); dropped != 1 {
		t.Fatalf("%v refusals were counted as dropped, and 1 was", dropped)
	}
	if published := counted(t, opened.registry, `seagull_ingest_refusals_total{outcome="published"}`); published != 2 {
		t.Fatalf("%v refusals were counted as published, and 2 were", published)
	}
}
