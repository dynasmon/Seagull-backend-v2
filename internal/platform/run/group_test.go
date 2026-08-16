package run_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestGroupWithoutMembersIsARefusal(t *testing.T) {
	group := run.NewGroup(quietLogger(), time.Second)
	if err := group.Run(context.Background()); err == nil {
		t.Fatal("expected an empty group to be rejected")
	}
}

func TestCancellationStopsEveryMember(t *testing.T) {
	group := run.NewGroup(quietLogger(), time.Second)
	var stopped atomic.Int32
	for range 3 {
		group.Add(run.Func("member", func(ctx context.Context) error {
			<-ctx.Done()
			stopped.Add(1)
			return ctx.Err()
		}))
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- group.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a cancelled group must not report failure: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("group did not stop after cancellation")
	}
	if stopped.Load() != 3 {
		t.Fatalf("expected 3 members to stop, got %d", stopped.Load())
	}
}

func TestOneFailureStopsTheProcess(t *testing.T) {
	group := run.NewGroup(quietLogger(), time.Second)
	peerStopped := make(chan struct{})

	group.Add(run.Func("broken", func(context.Context) error {
		return errors.New("bind failed")
	}))
	group.Add(run.Func("peer", func(ctx context.Context) error {
		<-ctx.Done()
		close(peerStopped)
		return nil
	}))

	err := group.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bind failed") {
		t.Fatalf("expected the failure to surface, got %v", err)
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Fatalf("expected the failing component to be named, got %v", err)
	}
	select {
	case <-peerStopped:
	default:
		t.Fatal("the peer component was not stopped")
	}
}

func TestAMemberReturningEarlyStopsTheProcess(t *testing.T) {
	group := run.NewGroup(quietLogger(), time.Second)
	group.Add(run.Func("finished", func(context.Context) error { return nil }))

	blocked := make(chan struct{})
	group.Add(run.Func("blocked", func(ctx context.Context) error {
		<-ctx.Done()
		close(blocked)
		return nil
	}))

	if err := group.Run(context.Background()); err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	<-blocked
}

func TestHungMemberIsReportedInsteadOfHangingForever(t *testing.T) {
	group := run.NewGroup(quietLogger(), 50*time.Millisecond)
	release := make(chan struct{})
	defer close(release)

	group.Add(run.Func("trigger", func(context.Context) error { return nil }))
	group.Add(run.Func("hung", func(context.Context) error {
		<-release
		return nil
	}))

	started := time.Now()
	err := group.Run(context.Background())

	if err == nil || !strings.Contains(err.Error(), "shutdown exceeded") {
		t.Fatalf("expected a shutdown timeout, got %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("group waited far past the shutdown budget")
	}
}
