package health

import (
	"context"
	"sort"
	"sync"
	"time"
)

type Status string

const (
	StatusOK       Status = "ok"
	StatusDegraded Status = "degraded"
	StatusDraining Status = "draining"
)

type Check func(ctx context.Context) error

type ComponentReport struct {
	Name    string
	Status  Status
	Failure string
	Latency time.Duration
}

type Report struct {
	Status     Status
	Components []ComponentReport
}

func (r Report) Ready() bool { return r.Status == StatusOK }

type Registry struct {
	ttl          time.Duration
	checkTimeout time.Duration
	now          func() time.Time

	mu       sync.Mutex
	checks   map[string]Check
	draining bool
	cached   Report
	cachedAt time.Time
}

type Option func(*Registry)

func WithClock(now func() time.Time) Option {
	return func(r *Registry) { r.now = now }
}

func New(ttl, checkTimeout time.Duration, options ...Option) *Registry {
	registry := &Registry{
		ttl:          ttl,
		checkTimeout: checkTimeout,
		now:          time.Now,
		checks:       map[string]Check{},
	}
	for _, option := range options {
		option(registry)
	}
	return registry
}

func (r *Registry) Register(name string, check Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks[name] = check
	r.cachedAt = time.Time{}
}

func (r *Registry) Drain() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.draining = true
	r.cachedAt = time.Time{}
}

func (r *Registry) Readiness(ctx context.Context) Report {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.draining {
		return Report{Status: StatusDraining}
	}
	if !r.cachedAt.IsZero() && r.now().Sub(r.cachedAt) < r.ttl {
		return r.cached
	}

	report := r.evaluate(ctx)
	r.cached = report
	r.cachedAt = r.now()
	return report
}

func (r *Registry) evaluate(ctx context.Context) Report {
	names := make([]string, 0, len(r.checks))
	for name := range r.checks {
		names = append(names, name)
	}
	sort.Strings(names)

	report := Report{Status: StatusOK, Components: make([]ComponentReport, 0, len(names))}
	for _, name := range names {
		check := r.checks[name]
		started := r.now()

		checkCtx, cancel := context.WithTimeout(ctx, r.checkTimeout)
		err := check(checkCtx)
		cancel()

		component := ComponentReport{Name: name, Status: StatusOK, Latency: r.now().Sub(started)}
		if err != nil {
			component.Status = StatusDegraded
			component.Failure = err.Error()
			report.Status = StatusDegraded
		}
		report.Components = append(report.Components, component)
	}
	return report
}
