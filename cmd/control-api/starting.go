package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
)

const startingNote = "the rules this installation starts from"

// The rule tree the engine starts on becomes the installation's first
// publication, between the replay of the log and the listener opening, so no
// caller can publish before it and a rule an engine already ran cannot be
// published again at its revision asking something else (ADR 51). Every start
// decides again from what the log holds: what is recorded is found recorded,
// and the pointer is moved only while no person has written it.
func (r rulesets) starting(ctx context.Context, tree fs.FS, at time.Time, logger *slog.Logger) error {
	written, err := rulefile.Rules(tree)
	if err != nil {
		return fmt.Errorf("read the rules this installation starts from: %w", err)
	}

	if len(written) == 0 {
		logger.Warn("starting_ruleset_empty", slog.String("active", r.catalogue.Activation().GetRulesetId()))
		return nil
	}

	if report := rulefile.Checked(written); !report.Held() {
		unheld := make([]error, 0, len(report.Unheld))
		for _, one := range report.Unheld {
			unheld = append(unheld, one)
		}
		return fmt.Errorf("the rules this installation starts from contradict their own cases: %w", errors.Join(unheld...))
	}

	programs, cases := composed(written)
	version, err := ruleset.NewVersion(programs, cases, ruleset.Installation, at, startingNote)
	if err != nil {
		return err
	}

	if !r.catalogue.Published(version.ID()) {
		if err := r.catalogue.Admits(version); err != nil {
			var conflict *ruleset.Conflict
			if !errors.As(err, &conflict) {
				return err
			}
			logger.Error("starting_ruleset_refused",
				slog.String("ruleset", string(version.ID())),
				slog.String("rule", string(conflict.Rule)),
				slog.Int("revision", conflict.Revision),
				slog.String("active", r.catalogue.Activation().GetRulesetId()),
			)
			return nil
		}

		record := version.Record()
		if size := proto.Size(record); size > r.largest {
			return fmt.Errorf("the rules this installation starts from encode to %d bytes, and the log they are published to carries at most %d", size, r.largest)
		}
		if err := r.publisher.Publish(ctx, record); err != nil {
			return fmt.Errorf("publish the rules this installation starts from: %w", err)
		}
		if err := r.catalogue.Apply(record); err != nil {
			return err
		}
		logger.Info("starting_ruleset_published",
			slog.String("ruleset", string(version.ID())),
			slog.Int("rules", version.Snapshot().Rules()),
		)
	}

	if !r.catalogue.Yields(version.ID()) {
		return nil
	}
	activated, err := r.Activate(ctx, string(version.ID()), startingNote, ruleset.Installation, at)
	if err != nil {
		return fmt.Errorf("activate the rules this installation starts from: %w", err)
	}
	logger.Info("starting_ruleset_activated",
		slog.String("ruleset", string(version.ID())),
		slog.String("replaced", activated.GetReplaced()),
	)
	return nil
}
