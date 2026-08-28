// Package control is the administrative surface of the platform: who a caller
// is, what the policy says they may do, and the sessions they hold while they do
// it. It decides nothing about authorisation itself — authz does that — and it
// reads no store.
package control

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
)

type Source interface {
	Policy() (*authz.Policy, error)
}

type SourceFunc func() (*authz.Policy, error)

func (f SourceFunc) Policy() (*authz.Policy, error) { return f() }

type RegistryOptions struct {
	Source  Source
	Metrics *Metrics
	Logger  *slog.Logger
}

// What a process decides against, and the only thing that can change it.
// Reading the current policy takes no lock and blocks on nothing: it happens
// once per request, and a reload must never be able to hold a request still.
type Registry struct {
	source  Source
	metrics *Metrics
	logger  *slog.Logger

	current atomic.Pointer[authz.Policy]
	loading sync.Mutex
}

func NewRegistry(options RegistryOptions) (*Registry, error) {
	switch {
	case options.Source == nil:
		return nil, errors.New("a policy registry needs a source")
	case options.Metrics == nil:
		return nil, errors.New("a policy registry needs metrics")
	case options.Logger == nil:
		return nil, errors.New("a policy registry needs a logger")
	}

	registry := &Registry{source: options.Source, metrics: options.Metrics, logger: options.Logger}
	policy, err := registry.read()
	if err != nil {
		return nil, err
	}
	registry.Replace(policy)
	return registry, nil
}

func (r *Registry) Current() *authz.Policy { return r.current.Load() }

func (r *Registry) Replace(policy *authz.Policy) *authz.Policy {
	if policy == nil {
		return r.Current()
	}
	previous := r.current.Swap(policy)
	if previous == nil || previous.ID() != policy.ID() {
		r.logger.Info("policy_pinned",
			slog.String("policy", policy.ID().String()),
			slog.Int("roles", policy.Roles()),
			slog.Int("bindings", policy.Bindings()),
		)
	}
	r.metrics.pinned(policy)
	return previous
}

func (r *Registry) Reload() error {
	r.loading.Lock()
	defer r.loading.Unlock()

	policy, err := r.read()
	if err != nil {
		r.metrics.reloaded("refused")
		r.logger.Error("policy_reload_refused", slog.String("error", err.Error()))
		return err
	}
	if current := r.Current(); current != nil && current.ID() == policy.ID() {
		r.metrics.reloaded("unchanged")
		return nil
	}
	r.Replace(policy)
	r.metrics.reloaded("replaced")
	return nil
}

func (r *Registry) read() (*authz.Policy, error) {
	policy, err := r.source.Policy()
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.New("the policy source produced nothing")
	}
	return policy, nil
}
