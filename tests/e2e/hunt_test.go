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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/tlsx"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

type answering struct {
	events []*eventv1.Event
	asked  hunt.Query
}

func (a *answering) Events(_ context.Context, query hunt.Query) ([]*eventv1.Event, error) {
	a.asked = query
	return a.events, nil
}

func (a *answering) Detections(_ context.Context, query hunt.Query) ([]*detectionv1.Detection, error) {
	a.asked = query
	return nil, nil
}

type queryPlane struct {
	address   string
	authority *devpki.Authority
	store     *answering
	stopped   chan error
}

func startQueryAPI(t *testing.T, store *answering) *queryPlane {
	t.Helper()

	authority, err := devpki.NewAuthority("Seagull Query Test CA", time.Hour)
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	server, err := authority.IssueServer("query-api", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("issue server certificate: %v", err)
	}

	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "query.pem")
	keyFile := filepath.Join(directory, "query-key.pem")
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
		Name:             "query-api",
		LogLevel:         "error",
		LogFormat:        "json",
		OpsAddress:       "127.0.0.1:0",
		ShutdownTimeout:  5 * time.Second,
		ReadinessTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("build service: %v", err)
	}

	compiler, err := hunt.NewCompiler(hunt.CompilerOptions{
		Limits: hunt.Limits{
			Window: 720 * time.Hour, Page: 50, MaxPage: 500,
			Timeout: 5 * time.Second, MaxRowsRead: 1_000_000,
		},
		CursorKey: bytes.Repeat([]byte("k"), 32),
	})
	if err != nil {
		t.Fatalf("build compiler: %v", err)
	}

	hunter, err := hunt.NewHunter(hunt.HunterOptions{
		Source:   store,
		Compiler: compiler,
		Metrics:  hunt.NewMetrics(platform.Metrics()),
		Logger:   platform.Logger(),
	})
	if err != nil {
		t.Fatalf("build hunter: %v", err)
	}

	listener, err := hunt.NewServer(hunt.ServerOptions{
		Address:         "127.0.0.1:0",
		TLS:             mutual,
		Hunter:          hunter,
		Instrumentation: platform.HTTP(),
		Logger:          platform.Logger(),
		MaxBodyBytes:    256 << 10,
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     30 * time.Second,
		ShutdownTimeout: platform.ShutdownTimeout(),
	})
	if err != nil {
		t.Fatalf("build listener: %v", err)
	}
	platform.Add(listener)

	ctx, cancel := context.WithCancel(context.Background())
	running := &queryPlane{
		address:   listener.Address(),
		authority: authority,
		store:     store,
		stopped:   make(chan error, 1),
	}
	go func() { running.stopped <- platform.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-running.stopped:
			if err != nil {
				t.Errorf("the query plane stopped with an error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("the query plane did not stop")
		}
	})
	return running
}

func (q *queryPlane) caller(t *testing.T, name string, tenants []string) *http.Client {
	t.Helper()

	material, err := q.authority.IssueCaller(name, tenants, time.Hour)
	if err != nil {
		t.Fatalf("issue caller certificate: %v", err)
	}
	return q.clientWith(t, material)
}

func (q *queryPlane) clientWith(t *testing.T, material devpki.Material) *http.Client {
	t.Helper()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(q.authority.Material().CertificatePEM) {
		t.Fatal("the test authority certificate is unusable")
	}

	settings := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if len(material.CertificatePEM) > 0 {
		keypair, err := tls.X509KeyPair(material.CertificatePEM, material.PrivateKeyPEM)
		if err != nil {
			t.Fatalf("load the caller keypair: %v", err)
		}
		settings.Certificates = []tls.Certificate{keypair}
	}

	transport := &http.Transport{TLSClientConfig: settings}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func (q *queryPlane) ask(t *testing.T, client *http.Client, query *huntv1.Query) (*http.Response, []byte) {
	t.Helper()

	encoded, err := proto.Marshal(query)
	if err != nil {
		t.Fatalf("encode the query: %v", err)
	}

	response, err := client.Post("https://"+q.address+hunt.EventsPath, hunt.ContentType, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("ask the query plane: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	return response, body
}

func lastHour() *huntv1.TimeRange {
	now := time.Now().UTC()
	return &huntv1.TimeRange{Start: timestamppb.New(now.Add(-time.Hour)), End: timestamppb.New(now)}
}

// The scope a query is answered within comes off the wire with the connection.
// A caller whose certificate names the tenant reads it, and the store is asked
// for that tenant and no other.
func TestTheQueryPlaneAnswersWithinTheCertificatesScope(t *testing.T) {
	plane := startQueryAPI(t, &answering{events: []*eventv1.Event{{
		EventId:    "aaaa-1111",
		EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Time:       &eventv1.Timestamps{EventTime: timestamppb.New(time.Now().UTC())},
	}}})

	response, body := plane.ask(t, plane.caller(t, "analyst-01", []string{"acme"}),
		&huntv1.Query{Range: lastHour()})

	if response.StatusCode != http.StatusOK {
		t.Fatalf("a scoped caller was answered with %d: %s", response.StatusCode, body)
	}
	var page huntv1.EventPage
	if err := proto.Unmarshal(body, &page); err != nil {
		t.Fatalf("read the page: %v", err)
	}
	if len(page.GetEvents()) != 1 || page.GetEvents()[0].GetEventId() != "aaaa-1111" {
		t.Errorf("the page carried %d events", len(page.GetEvents()))
	}
	if tenants := plane.store.asked.Scope().Tenants(); len(tenants) != 1 || tenants[0] != "acme" {
		t.Errorf("the store was asked for %v", tenants)
	}
}

// The listener terminates mutual TLS itself, so a caller with no certificate
// never reaches a handler at all: the refusal is the handshake.
func TestACallerWithNoCertificateNeverReachesTheStore(t *testing.T) {
	store := &answering{}
	plane := startQueryAPI(t, store)

	encoded, err := proto.Marshal(&huntv1.Query{Range: lastHour()})
	if err != nil {
		t.Fatalf("encode the query: %v", err)
	}
	client := plane.clientWith(t, devpki.Material{})
	if _, err := client.Post("https://"+plane.address+hunt.EventsPath, hunt.ContentType, bytes.NewReader(encoded)); err == nil {
		t.Fatal("a caller with no certificate was served")
	}
	if store.asked.Limit() != 0 {
		t.Error("a caller with no certificate reached the store")
	}
}

// A certificate the authority signed but which names no tenant authorises
// nothing. An empty scope reads nothing rather than everything.
func TestACallerAuthorisedForNothingReadsNothing(t *testing.T) {
	store := &answering{}
	plane := startQueryAPI(t, store)

	response, body := plane.ask(t, plane.caller(t, "analyst-02", nil), &huntv1.Query{Range: lastHour()})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("a caller with no tenant was answered with %d: %s", response.StatusCode, body)
	}

	var refusal huntv1.Refusal
	if err := proto.Unmarshal(body, &refusal); err != nil {
		t.Fatalf("read the refusal: %v", err)
	}
	if refusal.GetCode() != hunt.CodeUnscoped {
		t.Errorf("refused as %q", refusal.GetCode())
	}
	if store.asked.Limit() != 0 {
		t.Error("a caller authorised for nothing reached the store")
	}
}

// A caller signed by an authority this plane does not trust is refused at the
// handshake, whatever the certificate claims about who they are.
func TestACallerFromAnotherAuthorityIsRefused(t *testing.T) {
	plane := startQueryAPI(t, &answering{})

	foreign, err := devpki.NewAuthority("Someone Else CA", time.Hour)
	if err != nil {
		t.Fatalf("create the foreign authority: %v", err)
	}
	material, err := foreign.IssueCaller("analyst-01", []string{"acme"}, time.Hour)
	if err != nil {
		t.Fatalf("issue the foreign certificate: %v", err)
	}

	encoded, err := proto.Marshal(&huntv1.Query{Range: lastHour()})
	if err != nil {
		t.Fatalf("encode the query: %v", err)
	}
	client := plane.clientWith(t, material)
	if _, err := client.Post("https://"+plane.address+hunt.EventsPath, hunt.ContentType, bytes.NewReader(encoded)); err == nil {
		t.Fatal("a caller from an authority this plane does not trust was served")
	}
}

// A query the plane will not put to the store is refused with the field at
// fault, and the store is never asked.
func TestAQueryTheStoreWouldNotUnderstandNeverReachesIt(t *testing.T) {
	store := &answering{}
	plane := startQueryAPI(t, store)

	response, body := plane.ask(t, plane.caller(t, "analyst-01", []string{"acme"}), &huntv1.Query{
		Range: lastHour(),
		Where: &huntv1.Expression{Form: &huntv1.Expression_Predicate{Predicate: &huntv1.Predicate{
			Field: "authentication.user.password", Operator: huntv1.Operator_OPERATOR_EQUALS, Values: []string{"x"},
		}}},
	})

	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a query naming a field nobody stores was answered with %d: %s", response.StatusCode, body)
	}
	if store.asked.Limit() != 0 {
		t.Error("a refused query reached the store")
	}
}
