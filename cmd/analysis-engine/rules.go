package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

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

// The published rulesets this engine has read, and the pin it keeps on the one
// the control plane says to run. The engine itself never learns any of this: it
// asks the registry what to decide against, exactly as before.
type rulesetLog struct {
	catalogue *ruleset.Catalogue
	reader    *broker.RulesetLog
}

func publishedRulesets(ctx context.Context, settings configuration, platform *service.Service, registry *ruleset.Registry) (rulesetLog, error) {
	reader, err := broker.NewRulesetLog(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Rulesets.Name,
		ClientID: serviceName,
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
	if err := reader.Replay(startCtx, held.applying(platform.Logger(), registry)); err != nil {
		reader.Close()
		return rulesetLog{}, err
	}
	return held, nil
}

func (l rulesetLog) applying(logger *slog.Logger, registry *ruleset.Registry) broker.Deliver {
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
		l.pin(registry)
		return nil
	}
}

// Swapped only when the active pointer names something else, and only for a
// ruleset that is already composed: the registry holds the same snapshot for
// the whole of an event's evaluation, so a rollout never moves a rule out from
// under an event halfway through being decided.
func (l rulesetLog) pin(registry *ruleset.Registry) {
	version, published := l.catalogue.Active()
	if !published {
		return
	}
	if current := registry.Current(); current != nil && current.ID() == version.ID() {
		return
	}
	registry.Replace(version.Snapshot())
}

func (l rulesetLog) follower(logger *slog.Logger, registry *ruleset.Registry) follower {
	return follower{reader: l.reader, deliver: l.applying(logger, registry)}
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
