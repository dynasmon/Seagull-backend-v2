package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
)

// The second bridge this executable owns, for the same reason as the first:
// holding a ruleset and running one are separate capabilities, and neither
// names the other, so composing them is an executable's job.

type rules struct{ registry *ruleset.Registry }

func (r rules) Current() analysis.Ruleset {
	snapshot := r.registry.Current()
	if snapshot == nil {
		return nil
	}
	return pinned{Snapshot: snapshot}
}

type pinned struct{ *ruleset.Snapshot }

func (p pinned) ID() string { return string(p.Snapshot.ID()) }

// Where a ruleset comes from today: a tree of rule files under a directory this
// process is pointed at, read once at startup. A control plane replaces this
// without the registry, the engine or the rules changing.
func written(directory string) ruleset.SourceFunc {
	return func() ([]*detection.Program, error) { return rulefile.Read(os.DirFS(directory)) }
}

func recovering(engine runtime, partitions int32, registry *ruleset.Registry, logger *slog.Logger) broker.Recovery {
	return func(held int32) (time.Duration, error) {
		current := registry.Current()
		if err := engine.owns(current, held, partitions); err != nil {
			return 0, err
		}
		window := engine.recovering(current)
		logger.Info("partitions_assigned",
			slog.Int("held", int(held)),
			slog.Int("partitions", int(partitions)),
			slog.String("ruleset", running(current)),
			slog.Duration("rebuilding", window),
		)
		return window, nil
	}
}

// The published rulesets this engine has read, and the pin it keeps on the one
// the control plane says to run. The engine itself never learns any of this: it
// asks the registry what to decide against, exactly as before.
type rulesetLog struct {
	catalogue *ruleset.Catalogue
	reader    *broker.RulesetLog
}

func publishedRulesets(ctx context.Context, settings configuration, platform *service.Service, registry *ruleset.Registry, engine runtime) (rulesetLog, error) {
	reader, err := broker.NewRulesetLog(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Rulesets.Name,
		ClientID: serviceName,
		Security: settings.security,
	}, settings.logRecords)
	if err != nil {
		return rulesetLog{}, err
	}
	held := rulesetLog{catalogue: ruleset.NewCatalogue(), reader: reader}

	startCtx, cancel := context.WithTimeout(ctx, settings.startTimeout)
	defer cancel()

	drift, err := reader.VerifyTopics(startCtx, settings.topology.Rulesets)
	if err != nil {
		reader.Close()
		return rulesetLog{}, err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}
	if err := reader.Replay(startCtx, held.applying(platform.Logger(), registry, engine)); err != nil {
		reader.Close()
		return rulesetLog{}, err
	}
	return held, nil
}

func (l rulesetLog) applying(logger *slog.Logger, registry *ruleset.Registry, engine runtime) broker.Deliver {
	return func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			if err := l.catalogue.Read(record.Value); err != nil {
				logger.Warn("ruleset_record_refused",
					slog.Int64("offset", record.Offset),
					slog.String("key", string(record.Key)),
					slog.String("error", err.Error()),
				)
			}
		}
		l.pin(registry, engine, logger)
		return nil
	}
}

// Swapped only when the active pointer names something else, so a rollout
// never moves a rule out from under an event halfway through being decided.
// Compiling is not enough to run: a ruleset this deployment could only answer
// partially is refused whole, and the last one it could answer keeps running.
func (l rulesetLog) pin(registry *ruleset.Registry, engine runtime, logger *slog.Logger) {
	version, published := l.catalogue.Active()
	if !published {
		return
	}
	current := registry.Current()
	if current != nil && current.ID() == version.ID() {
		return
	}

	snapshot := version.Snapshot()
	if err := engine.admits(snapshot); err != nil {
		registry.Refuse()
		logger.Error("ruleset_not_executable",
			slog.String("ruleset", string(version.ID())),
			slog.String("running", running(current)),
			slog.String("error", err.Error()),
		)
		return
	}
	registry.Replace(snapshot)
}

func running(current *ruleset.Snapshot) string {
	if current == nil {
		return ""
	}
	return string(current.ID())
}

func (l rulesetLog) follower(logger *slog.Logger, registry *ruleset.Registry, engine runtime) follower {
	return follower{reader: l.reader, deliver: l.applying(logger, registry, engine)}
}

type follower struct {
	reader  *broker.RulesetLog
	deliver broker.Deliver
}

func (f follower) Name() string { return "ruleset-log" }

func (f follower) Run(ctx context.Context) error {
	if err := f.reader.Follow(ctx, f.deliver); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
