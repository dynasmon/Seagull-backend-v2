//go:build load

package load_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/tlsx"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

func brokers(t *testing.T) []string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("SEAGULL_TEST_BROKERS"))
	if value == "" {
		t.Skip("set SEAGULL_TEST_BROKERS to run the load suite")
	}
	return strings.Split(value, ",")
}

// A backbone that counts what it was given and can be held open, so a scenario
// can measure what the gateway does while its only durable destination is slow.
type controlledBackbone struct {
	events  atomic.Int64
	batches atomic.Int64
	delay   time.Duration
	hold    chan struct{}

	mu    sync.Mutex
	kept  bool
	seen  map[string]struct{}
	inUse atomic.Int64
	peak  atomic.Int64
}

func newControlledBackbone() *controlledBackbone {
	return &controlledBackbone{seen: map[string]struct{}{}}
}

func (c *controlledBackbone) keepIdentities() *controlledBackbone {
	c.kept = true
	return c
}

func (c *controlledBackbone) PublishEvents(ctx context.Context, events []*eventv1.Event) error {
	inFlight := c.inUse.Add(1)
	defer c.inUse.Add(-1)
	for {
		highest := c.peak.Load()
		if inFlight <= highest || c.peak.CompareAndSwap(highest, inFlight) {
			break
		}
	}

	if c.hold != nil {
		select {
		case <-c.hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if c.kept {
		c.mu.Lock()
		for _, record := range events {
			c.seen[record.GetEventId()] = struct{}{}
		}
		c.mu.Unlock()
	}

	c.batches.Add(1)
	c.events.Add(int64(len(events)))
	return nil
}

func (c *controlledBackbone) holds(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, held := c.seen[id]
	return held
}

type gateway struct {
	address   string
	authority *devpki.Authority
	stopped   chan error
	stop      context.CancelFunc
	once      sync.Once
	failure   error
}

func (g *gateway) awaitStop(budget time.Duration) error {
	g.once.Do(func() {
		select {
		case g.failure = <-g.stopped:
		case <-time.After(budget):
			g.failure = errors.New("the gateway did not stop")
		}
	})
	return g.failure
}

type gatewayOptions struct {
	backbone          ingest.Backbone
	maxBodyBytes      int64
	maxEventsPerBatch int
	ratePerSecond     float64
	rateBurst         int
	trackedAgents     int
	publishTimeout    time.Duration
}

func startGateway(t *testing.T, options gatewayOptions) *gateway {
	t.Helper()

	if options.maxBodyBytes == 0 {
		options.maxBodyBytes = 8 << 20
	}
	if options.maxEventsPerBatch == 0 {
		options.maxEventsPerBatch = 10_000
	}
	if options.trackedAgents == 0 {
		options.trackedAgents = 10_000
	}
	if options.publishTimeout == 0 {
		options.publishTimeout = 10 * time.Second
	}
	if options.backbone == nil {
		options.backbone = newControlledBackbone()
	}

	authority, err := devpki.NewAuthority("Seagull Load CA", time.Hour)
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
		ShutdownTimeout:  20 * time.Second,
		ReadinessCache:   0,
		ReadinessTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("build service: %v", err)
	}

	admitter, err := ingest.NewAdmitter(options.backbone, ingest.Policy{
		Gateway:           "gateway-load",
		TenantID:          "acme",
		MaxEventsPerBatch: options.maxEventsPerBatch,
		Event:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
	}, ingest.NewMetrics(platform.Metrics()))
	if err != nil {
		t.Fatalf("build admitter: %v", err)
	}

	var limiter *ratelimit.Limiter
	if options.ratePerSecond > 0 {
		limiter = ratelimit.NewLimiter(options.ratePerSecond, options.rateBurst, options.trackedAgents)
	}

	handler, err := ingest.NewHandler(ingest.HandlerOptions{
		Admitter:       admitter,
		Limiter:        limiter,
		MaxBodyBytes:   options.maxBodyBytes,
		PublishTimeout: options.publishTimeout,
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
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     60 * time.Second,
		ShutdownTimeout: platform.ShutdownTimeout(),
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	platform.Add(listener)

	ctx, cancel := context.WithCancel(context.Background())
	running := &gateway{
		address:   listener.Address(),
		authority: authority,
		stopped:   make(chan error, 1),
		stop:      cancel,
	}
	go func() { running.stopped <- platform.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		if err := running.awaitStop(30 * time.Second); err != nil {
			t.Errorf("gateway: %v", err)
		}
	})
	return running
}

func (g *gateway) client(t *testing.T, agentID string) *http.Client {
	t.Helper()

	client, err := g.authority.IssueClient(agentID, time.Hour)
	if err != nil {
		t.Fatalf("issue client certificate: %v", err)
	}
	keypair, err := tls.X509KeyPair(client.CertificatePEM, client.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(g.authority.Material().CertificatePEM) {
		t.Fatal("the load authority certificate is unusable")
	}

	agent := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{keypair}, MinVersion: tls.VersionTLS13},
			MaxIdleConnsPerHost: 64,
		},
		Timeout: 60 * time.Second,
	}
	t.Cleanup(agent.CloseIdleConnections)
	return agent
}

func write(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func batchOf(agentID string, sequence, size int) *ingestv1.EventBatch {
	at := time.Now().UTC()
	events := make([]*eventv1.Event, 0, size)
	for index := range size {
		events = append(events, fixtures.SSHAuthentication{
			EventID:  fmt.Sprintf("%s-%d-%d", agentID, sequence, index),
			AgentID:  agentID,
			At:       at,
			Sequence: uint64(index),
		}.Event())
	}
	return fixtures.Batch(fmt.Sprintf("%s-%d", agentID, sequence), events...)
}

func encodeBatch(t *testing.T, batch *ingestv1.EventBatch) []byte {
	t.Helper()
	payload, err := proto.Marshal(batch)
	if err != nil {
		t.Fatalf("encode batch: %v", err)
	}
	return payload
}

type outcome struct {
	status  int
	latency time.Duration
	batch   *ingestv1.EventBatch
}

func (g *gateway) send(client *http.Client, payload []byte) (int, error) {
	request, err := http.NewRequest(http.MethodPost, "https://"+g.address+ingest.EventsPath, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", ingest.ContentType)

	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode, nil
}

// One agent is one goroutine holding one connection, which is the shape the
// gateway actually meets: an agent sends its next batch after the last answer.
type driveOptions struct {
	agents    int
	batchSize int
	batches   int
	duration  time.Duration
	tolerant  bool
	prefix    string
}

func drive(t *testing.T, running *gateway, options driveOptions) []outcome {
	t.Helper()

	if options.prefix == "" {
		options.prefix = "load-agent"
	}
	deadline := time.Now().Add(options.duration)
	results := make([][]outcome, options.agents)

	var group sync.WaitGroup
	for agent := range options.agents {
		agentID := fmt.Sprintf("%s-%04d", options.prefix, agent)
		client := running.client(t, agentID)

		group.Add(1)
		go func() {
			defer group.Done()
			for sequence := 0; ; sequence++ {
				if options.batches > 0 && sequence >= options.batches {
					return
				}
				if options.duration > 0 && time.Now().After(deadline) {
					return
				}

				batch := batchOf(agentID, sequence, options.batchSize)
				payload := encodeBatch(t, batch)

				started := time.Now()
				status, err := running.send(client, payload)
				elapsed := time.Since(started)
				if err != nil {
					if !options.tolerant {
						t.Errorf("agent %s: send batch %d: %v", agentID, sequence, err)
					}
					return
				}
				results[agent] = append(results[agent], outcome{status: status, latency: elapsed, batch: batch})
			}
		}()
	}
	group.Wait()

	var all []outcome
	for _, agent := range results {
		all = append(all, agent...)
	}
	return all
}

type summary struct {
	batches       int
	events        int
	accepted      int
	elapsed       time.Duration
	p50, p95, p99 time.Duration
	max           time.Duration
	bytesPerEvent float64
	goroutines    int
}

func summarise(outcomes []outcome, elapsed time.Duration, allocated uint64, goroutines int) summary {
	latencies := make([]time.Duration, 0, len(outcomes))
	result := summary{elapsed: elapsed, goroutines: goroutines}

	for _, entry := range outcomes {
		result.batches++
		result.events += len(entry.batch.GetEvents())
		if entry.status == http.StatusOK {
			result.accepted++
		}
		latencies = append(latencies, entry.latency)
	}
	if len(latencies) == 0 {
		return result
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	result.p50 = latencies[len(latencies)*50/100]
	result.p95 = latencies[min(len(latencies)*95/100, len(latencies)-1)]
	result.p99 = latencies[min(len(latencies)*99/100, len(latencies)-1)]
	result.max = latencies[len(latencies)-1]
	if result.events > 0 {
		result.bytesPerEvent = float64(allocated) / float64(result.events)
	}
	return result
}

func (s summary) report(t *testing.T, name string) {
	t.Helper()
	t.Logf("%s: %d batches, %d events in %s — %.0f events/s, %d accepted",
		name, s.batches, s.events, s.elapsed.Round(time.Millisecond),
		float64(s.events)/s.elapsed.Seconds(), s.accepted)
	t.Logf("%s: p50 %s  p95 %s  p99 %s  max %s", name,
		s.p50.Round(time.Microsecond), s.p95.Round(time.Microsecond),
		s.p99.Round(time.Microsecond), s.max.Round(time.Microsecond))
	t.Logf("%s: %.0f bytes allocated per event, %d goroutines left running", name, s.bytesPerEvent, s.goroutines)
}

// Allocation is measured rather than heap size: bytes per event is the same
// number on any machine, and a regression that doubles it is what matters.
func measure(work func()) (time.Duration, uint64, int) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	settled := runtime.NumGoroutine()

	started := time.Now()
	work()
	elapsed := time.Since(started)

	runtime.ReadMemStats(&after)
	return elapsed, after.TotalAlloc - before.TotalAlloc, runtime.NumGoroutine() - settled
}

func temporaryTopic(t *testing.T, addresses []string) string {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	t.Cleanup(client.Close)

	admin := kadm.NewClient(client)
	topic := fmt.Sprintf("security.events.raw.load.%d", time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := admin.CreateTopic(ctx, 12, 1, map[string]*string{}, topic); err != nil {
		t.Fatalf("create topic: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.DeleteTopics(cleanup, topic)
	})
	return topic
}

func recordsOn(t *testing.T, addresses []string, topic string) int64 {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	offsets, err := kadm.NewClient(client).ListEndOffsets(ctx, topic)
	if err != nil {
		t.Fatalf("read the end of %s: %v", topic, err)
	}

	var total int64
	offsets.Each(func(offset kadm.ListedOffset) {
		if offset.Err == nil && offset.Offset > 0 {
			total += offset.Offset
		}
	})
	return total
}

func realBackbone(t *testing.T, addresses []string, topic string) *broker.Publisher {
	t.Helper()
	publisher, err := broker.NewPublisher(broker.Config{Brokers: addresses, Topic: topic, ClientID: "load-gateway"})
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	t.Cleanup(publisher.Close)
	return publisher
}
