package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type Runnable interface {
	Name() string
	Run(ctx context.Context) error
}

type funcRunnable struct {
	name string
	run  func(context.Context) error
}

func (f funcRunnable) Name() string { return f.name }

func (f funcRunnable) Run(ctx context.Context) error { return f.run(ctx) }

func Func(name string, run func(context.Context) error) Runnable {
	return funcRunnable{name: name, run: run}
}

func SignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
}

type Group struct {
	logger          *slog.Logger
	shutdownTimeout time.Duration
	members         []Runnable
}

func NewGroup(logger *slog.Logger, shutdownTimeout time.Duration) *Group {
	return &Group{logger: logger, shutdownTimeout: shutdownTimeout}
}

func (g *Group) Add(members ...Runnable) {
	g.members = append(g.members, members...)
}

type outcome struct {
	name string
	err  error
}

func (g *Group) Run(ctx context.Context) error {
	if len(g.members) == 0 {
		return errors.New("run group has no members")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan outcome, len(g.members))
	var running sync.WaitGroup
	for _, member := range g.members {
		running.Add(1)
		go func(member Runnable) {
			defer running.Done()
			results <- outcome{name: member.Name(), err: member.Run(runCtx)}
		}(member)
		g.logger.Info("component_started", slog.String("component", member.Name()))
	}

	var failures []error
	trigger := "signal"
	select {
	case first := <-results:
		trigger = first.name
		failures = append(failures, componentError(first)...)
	case <-ctx.Done():
	}

	cancel()
	g.logger.Info("shutdown_started",
		slog.String("trigger", trigger),
		slog.Duration("grace", g.shutdownTimeout),
	)

	stopped := make(chan struct{})
	go func() {
		running.Wait()
		close(stopped)
	}()

	timer := time.NewTimer(g.shutdownTimeout)
	defer timer.Stop()

	select {
	case <-stopped:
		close(results)
		for result := range results {
			failures = append(failures, componentError(result)...)
		}
	case <-timer.C:
		failures = append(failures, fmt.Errorf("shutdown exceeded %s", g.shutdownTimeout))
	}

	g.logger.Info("shutdown_completed", slog.Int("failures", len(failures)))
	return errors.Join(failures...)
}

func componentError(result outcome) []error {
	if result.err == nil || errors.Is(result.err, context.Canceled) {
		return nil
	}
	return []error{fmt.Errorf("%s: %w", result.name, result.err)}
}
