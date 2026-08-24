package ruleset

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// Where a ruleset comes from. A tree of rule files today and a control plane
// later; what comes back is compiled, so whatever produced it has already
// refused everything that would not have run.
type Source interface {
	Programs() ([]*detection.Program, error)
}

type SourceFunc func() ([]*detection.Program, error)

func (f SourceFunc) Programs() ([]*detection.Program, error) { return f() }

type Options struct {
	Source  Source
	Metrics *Metrics
	Logger  *slog.Logger
}

// What a process is pinned to, and the only thing that can change it. Reading
// the current ruleset takes no lock and blocks on nothing, because it happens
// once per event and a reload must never be able to hold the hot path still.
type Registry struct {
	source  Source
	metrics *Metrics
	logger  *slog.Logger

	current atomic.Pointer[Snapshot]
	loading sync.Mutex
}

// Reads the source once and pins the registry to what it holds. A process that
// cannot read its rules does not start: running against a ruleset nobody chose
// is worse than refusing to run.
func New(options Options) (*Registry, error) {
	switch {
	case options.Source == nil:
		return nil, errors.New("a ruleset registry needs a source")
	case options.Metrics == nil:
		return nil, errors.New("a ruleset registry needs metrics")
	case options.Logger == nil:
		return nil, errors.New("a ruleset registry needs a logger")
	}

	registry := &Registry{source: options.Source, metrics: options.Metrics, logger: options.Logger}
	snapshot, err := registry.read()
	if err != nil {
		return nil, err
	}
	registry.Replace(snapshot)
	return registry, nil
}

// The ruleset to decide an event against. Held for the whole of that work: a
// reload arriving in the middle replaces what the next event will be read
// against and never what this one is being read against.
func (r *Registry) Current() *Snapshot { return r.current.Load() }

// Pin the registry to a ruleset, and give back the one it replaced so that
// putting it back is a swap rather than another load.
func (r *Registry) Replace(snapshot *Snapshot) *Snapshot {
	if snapshot == nil {
		return r.Current()
	}

	r.loading.Lock()
	defer r.loading.Unlock()
	return r.replace(snapshot)
}

// Read the source again and pin the registry to what it holds now. Nothing is
// replaced unless the whole ruleset read and compiled, so a reload that fails
// leaves the process running exactly what it was running before.
func (r *Registry) Reload() (*Snapshot, error) {
	r.loading.Lock()
	defer r.loading.Unlock()

	snapshot, err := r.read()
	if err != nil {
		r.metrics.reloaded("refused")
		r.logger.Warn("ruleset_not_reloaded", slog.String("error", err.Error()))
		return nil, err
	}

	// The same rules read twice are the same ruleset, so a source that was
	// touched rather than changed does not restart the clock on what the
	// process has been running.
	if current := r.Current(); current != nil && current.ID() == snapshot.ID() {
		r.metrics.reloaded("unchanged")
		return current, nil
	}

	r.replace(snapshot)
	r.metrics.reloaded("applied")
	return snapshot, nil
}

func (r *Registry) replace(snapshot *Snapshot) *Snapshot {
	since := time.Now().UTC()
	previous := r.current.Swap(snapshot)
	r.metrics.pinned(snapshot, since)

	replaced := ID("")
	if previous != nil {
		replaced = previous.ID()
	}
	r.logger.Info("ruleset_pinned",
		slog.String("ruleset", string(snapshot.ID())),
		slog.String("replaced", string(replaced)),
		slog.Int("rules", snapshot.Rules()),
		slog.Int("running", snapshot.Running()),
	)

	// A ruleset that runs nothing is a legitimate state on a fresh deployment
	// and an invisible failure everywhere else, so it is said out loud.
	if snapshot.Running() == 0 {
		r.logger.Warn("ruleset_runs_nothing", slog.String("ruleset", string(snapshot.ID())))
	}
	return previous
}

func (r *Registry) read() (*Snapshot, error) {
	programs, err := r.source.Programs()
	if err != nil {
		return nil, err
	}
	return Compose(programs)
}
