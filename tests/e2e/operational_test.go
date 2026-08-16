package e2e_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

type operationalService struct {
	address string
	stopped chan error
	stop    context.CancelFunc
	service *service.Service
	client  *http.Client
}

func startService(t *testing.T) *operationalService {
	t.Helper()

	platform, err := service.New(service.Config{
		Name:             "foundation-test",
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

	idle := make(chan struct{})
	platform.Add(run.Func("idle", func(ctx context.Context) error {
		<-ctx.Done()
		close(idle)
		return nil
	}))

	client := &http.Client{Timeout: 10 * time.Second}
	t.Cleanup(client.CloseIdleConnections)

	ctx, cancel := context.WithCancel(context.Background())
	running := &operationalService{
		address: platform.OperationalAddress(),
		stopped: make(chan error, 1),
		stop:    cancel,
		service: platform,
		client:  client,
	}
	go func() { running.stopped <- platform.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-running.stopped:
			if err != nil {
				t.Errorf("service stopped with an error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("service did not stop")
		}
		<-idle
	})
	return running
}

func (o *operationalService) get(t *testing.T, path string) (int, string) {
	t.Helper()

	response, err := o.client.Get("http://" + o.address + path)
	if err != nil {
		t.Fatalf("call %s: %v", path, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return response.StatusCode, string(body)
}

func TestLivenessDoesNotProbeDependencies(t *testing.T) {
	platform := startService(t)
	platform.service.Health().Register("backbone", func(context.Context) error {
		t.Error("liveness probed a dependency")
		return nil
	})

	status, body := platform.get(t, "/healthz")

	if status != http.StatusOK || !strings.Contains(body, `"ok"`) {
		t.Fatalf("unexpected liveness answer %d %s", status, body)
	}
}

func TestReadinessFollowsItsChecks(t *testing.T) {
	platform := startService(t)

	failing := errors.New("no leader for partition security.events.raw on redpanda-2.internal")
	broken := true
	platform.service.Health().Register("backbone", func(context.Context) error {
		if broken {
			return failing
		}
		return nil
	})

	status, body := platform.get(t, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 while degraded, got %d", status)
	}
	if strings.Contains(body, "redpanda-2.internal") || strings.Contains(body, "backbone") {
		t.Fatalf("readiness described the platform's internals: %s", body)
	}

	broken = false
	if status, _ := platform.get(t, "/readyz"); status != http.StatusOK {
		t.Fatalf("expected 200 once healthy, got %d", status)
	}
}

func TestReadinessTurnsAwayTrafficWhileDraining(t *testing.T) {
	platform := startService(t)
	platform.service.Health().Register("backbone", func(context.Context) error { return nil })

	if status, _ := platform.get(t, "/readyz"); status != http.StatusOK {
		t.Fatal("the service was not ready before draining")
	}

	platform.service.Health().Drain()

	status, body := platform.get(t, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("a draining service must stop reporting ready, got %d", status)
	}
	if !strings.Contains(body, "draining") {
		t.Fatalf("expected a draining verdict, got %s", body)
	}
}

func TestMetricsCarryServiceIdentityAndTraffic(t *testing.T) {
	platform := startService(t)
	platform.get(t, "/healthz")

	status, body := platform.get(t, "/metrics")

	if status != http.StatusOK {
		t.Fatalf("unexpected metrics status %d", status)
	}
	for _, expected := range []string{
		`seagull_build_info{`,
		`service="foundation-test"`,
		`seagull_http_requests_total{`,
		`route="healthz"`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("%s missing from the exposition", expected)
		}
	}
}

func TestEveryComponentStopsWhenTheServiceStops(t *testing.T) {
	platform := startService(t)

	platform.stop()

	select {
	case err := <-platform.stopped:
		platform.stopped <- err
		if err != nil {
			t.Fatalf("clean shutdown reported a failure: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the service did not stop")
	}
}
