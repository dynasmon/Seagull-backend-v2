package health_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/health"
)

func TestReadyWhenEveryCheckPasses(t *testing.T) {
	registry := health.New(time.Second, time.Second)
	registry.Register("broker", func(context.Context) error { return nil })

	report := registry.Readiness(context.Background())

	if !report.Ready() {
		t.Fatalf("expected readiness, got %s", report.Status)
	}
	if len(report.Components) != 1 || report.Components[0].Name != "broker" {
		t.Fatalf("unexpected components: %+v", report.Components)
	}
}

func TestOneFailingCheckDegradesTheWhole(t *testing.T) {
	registry := health.New(time.Second, time.Second)
	registry.Register("broker", func(context.Context) error { return errors.New("no leader") })
	registry.Register("disk", func(context.Context) error { return nil })

	report := registry.Readiness(context.Background())

	if report.Ready() {
		t.Fatal("expected degraded readiness")
	}
	if report.Components[0].Failure != "no leader" {
		t.Fatalf("failure detail lost: %+v", report.Components[0])
	}
}

func TestChecksAreReusedWithinTheCacheWindow(t *testing.T) {
	var calls int
	current := time.Unix(0, 0)
	registry := health.New(5*time.Second, time.Second, health.WithClock(func() time.Time { return current }))
	registry.Register("broker", func(context.Context) error {
		calls++
		return nil
	})

	for range 30 {
		registry.Readiness(context.Background())
	}
	if calls != 1 {
		t.Fatalf("expected a single probe inside the window, got %d", calls)
	}

	current = current.Add(6 * time.Second)
	registry.Readiness(context.Background())
	if calls != 2 {
		t.Fatalf("expected a refresh after the window, got %d", calls)
	}
}

func TestDrainingStopsReportingReady(t *testing.T) {
	registry := health.New(time.Second, time.Second)
	registry.Register("broker", func(context.Context) error { return nil })
	if !registry.Readiness(context.Background()).Ready() {
		t.Fatal("expected readiness before draining")
	}

	registry.Drain()

	report := registry.Readiness(context.Background())
	if report.Ready() || report.Status != health.StatusDraining {
		t.Fatalf("expected draining, got %s", report.Status)
	}
}

func TestSlowCheckCannotHangReadiness(t *testing.T) {
	registry := health.New(0, 20*time.Millisecond)
	registry.Register("slow", func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})

	done := make(chan health.Report, 1)
	go func() { done <- registry.Readiness(context.Background()) }()

	select {
	case report := <-done:
		if report.Ready() {
			t.Fatal("a timed out check must not report ready")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readiness hung on a slow check")
	}
}

func TestConcurrentReadinessIsSafe(t *testing.T) {
	registry := health.New(time.Millisecond, time.Second)
	registry.Register("broker", func(context.Context) error { return nil })

	var group sync.WaitGroup
	for range 64 {
		group.Add(1)
		go func() {
			defer group.Done()
			registry.Readiness(context.Background())
		}()
	}
	group.Wait()
}
