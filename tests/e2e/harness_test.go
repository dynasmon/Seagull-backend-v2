package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/tlsx"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

type backbone struct {
	published []*eventv1.Event
	failure   error
	release   chan struct{}
	entered   chan struct{}
	arrived   sync.Once
}

func (b *backbone) PublishEvents(ctx context.Context, events []*eventv1.Event) error {
	if b.entered != nil {
		b.arrived.Do(func() { close(b.entered) })
	}
	if b.release != nil {
		select {
		case <-b.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if b.failure != nil {
		return b.failure
	}
	b.published = append(b.published, events...)
	return nil
}

type gateway struct {
	address    string
	opsAddress string
	authority  *devpki.Authority
	backbone   *backbone
	stopped    chan error
	stop       context.CancelFunc
}

type gatewayOptions struct {
	maxBodyBytes        int64
	maxEventsPerBatch   int
	ratePerSecond       float64
	rateBurst           int
	maxInflightBytes    int64
	maxInflightRequests int
	backbone            *backbone
}

func startGateway(t *testing.T, options gatewayOptions) *gateway {
	t.Helper()

	if options.maxBodyBytes == 0 {
		options.maxBodyBytes = 1 << 20
	}
	if options.maxEventsPerBatch == 0 {
		options.maxEventsPerBatch = 100
	}
	if options.maxInflightBytes == 0 {
		options.maxInflightBytes = 64 << 20
	}
	if options.maxInflightRequests == 0 {
		options.maxInflightRequests = 256
	}
	if options.backbone == nil {
		options.backbone = &backbone{}
	}

	authority, err := devpki.NewAuthority("Seagull Test CA", time.Hour)
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	server, err := authority.IssueServer("ingest-gateway", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("issue server certificate: %v", err)
	}

	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "gateway.pem")
	keyFile := filepath.Join(directory, "gateway-key.pem")
	authorityFile := filepath.Join(directory, "agent-ca.pem")
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
		Name:             "ingest-gateway",
		LogLevel:         "error",
		LogFormat:        "json",
		OpsAddress:       "127.0.0.1:0",
		ShutdownTimeout:  5 * time.Second,
		ReadinessCache:   0,
		ReadinessTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("build service: %v", err)
	}

	instruments := ingest.NewMetrics(platform.Metrics())
	admitter, err := ingest.NewAdmitter(options.backbone, ingest.Policy{
		Gateway:           "gateway-test",
		TenantID:          "acme",
		MaxEventsPerBatch: options.maxEventsPerBatch,
		Event:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
	}, instruments)
	if err != nil {
		t.Fatalf("build admitter: %v", err)
	}

	var limiter *ratelimit.Limiter
	if options.ratePerSecond > 0 {
		limiter = ratelimit.NewLimiter(options.ratePerSecond, options.rateBurst, 64)
	}

	capacity, err := ingest.NewCapacity(options.maxInflightBytes, options.maxInflightRequests)
	if err != nil {
		t.Fatalf("bound what the gateway holds at once: %v", err)
	}

	handler, err := ingest.NewHandler(ingest.HandlerOptions{
		Admitter:       admitter,
		Limiter:        limiter,
		Capacity:       capacity,
		Metrics:        instruments,
		MaxBodyBytes:   options.maxBodyBytes,
		PublishTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}

	listener, err := ingest.NewServer(ingest.ServerOptions{
		Address:         "127.0.0.1:0",
		TLS:             mutual,
		Handler:         handler,
		Instrumentation: platform.HTTP(),
		Logger:          platform.Logger(),
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    10 * time.Second,
		IdleTimeout:     30 * time.Second,
		ShutdownTimeout: platform.ShutdownTimeout(),
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	platform.Add(listener)

	ctx, cancel := context.WithCancel(context.Background())
	running := &gateway{
		address:    listener.Address(),
		opsAddress: platform.OperationalAddress(),
		authority:  authority,
		backbone:   options.backbone,
		stopped:    make(chan error, 1),
		stop:       cancel,
	}
	go func() { running.stopped <- platform.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		running.awaitStop(t, 10*time.Second)
	})
	return running
}

func (g *gateway) awaitStop(t *testing.T, budget time.Duration) {
	t.Helper()
	select {
	case err, open := <-g.stopped:
		if !open {
			return
		}
		close(g.stopped)
		if err != nil {
			t.Errorf("gateway stopped with an error: %v", err)
		}
	case <-time.After(budget):
		t.Error("gateway did not stop")
	}
}

func write(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func (g *gateway) client(t *testing.T, agentID string) *http.Client {
	t.Helper()
	client, err := g.authority.IssueClient(agentID, time.Hour)
	if err != nil {
		t.Fatalf("issue client certificate: %v", err)
	}
	return g.clientWith(t, client, g.authority.Material().CertificatePEM)
}

func (g *gateway) clientWith(t *testing.T, client devpki.Material, authorityPEM []byte) *http.Client {
	t.Helper()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authorityPEM) {
		t.Fatal("test authority certificate is unusable")
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	if len(client.CertificatePEM) > 0 {
		keypair, err := tls.X509KeyPair(client.CertificatePEM, client.PrivateKeyPEM)
		if err != nil {
			t.Fatalf("load client keypair: %v", err)
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{keypair}
	}
	agent := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	t.Cleanup(agent.CloseIdleConnections)
	return agent
}

func (g *gateway) anonymousClient(t *testing.T) *http.Client {
	t.Helper()
	return g.clientWith(t, devpki.Material{}, g.authority.Material().CertificatePEM)
}

func (g *gateway) url() string { return "https://" + g.address + ingest.EventsPath }

func (g *gateway) post(t *testing.T, client *http.Client, contentType string, body []byte) (*http.Response, []byte) {
	t.Helper()

	request, err := http.NewRequest(http.MethodPost, g.url(), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", contentType)

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return response, payload
}

func (g *gateway) send(t *testing.T, client *http.Client, batch *ingestv1.EventBatch) (*http.Response, []byte) {
	t.Helper()
	encoded, err := proto.Marshal(batch)
	if err != nil {
		t.Fatalf("encode batch: %v", err)
	}
	return g.post(t, client, ingest.ContentType, encoded)
}

func decodeAck(t *testing.T, payload []byte) *ingestv1.BatchAck {
	t.Helper()
	var acknowledgement ingestv1.BatchAck
	if err := proto.Unmarshal(payload, &acknowledgement); err != nil {
		t.Fatalf("decode acknowledgement: %v", err)
	}
	return &acknowledgement
}

func decodeRejection(t *testing.T, payload []byte) *ingestv1.Rejection {
	t.Helper()
	var rejection ingestv1.Rejection
	if err := proto.Unmarshal(payload, &rejection); err != nil {
		t.Fatalf("decode rejection: %v", err)
	}
	return &rejection
}

func isHandshakeFailure(err error) bool {
	if err == nil {
		return false
	}
	var recordError *tls.CertificateVerificationError
	if errors.As(err, &recordError) {
		return true
	}
	var alert tls.AlertError
	return errors.As(err, &alert)
}
