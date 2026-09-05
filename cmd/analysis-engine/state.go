package main

import (
	"fmt"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
)

// What this deployment can actually run: how much a store may hold and what
// the stream keeps together are two halves of one question, and only an
// executable knows both. A rule this cannot answer would run and never fire,
// or fire on part of what it was written to count.
type runtime struct {
	bounds       detectionstate.Bounds
	partitioning detectionstate.Partitioning
	skew         time.Duration
}

func (r runtime) validate() error {
	if err := r.bounds.Validate(); err != nil {
		return err
	}
	return r.partitioning.Validate()
}

// Active means executable, and a ruleset is admitted whole or not at all.
func (r runtime) admits(running *ruleset.Snapshot) error {
	if running == nil {
		return nil
	}
	for _, rule := range runs(running) {
		if err := r.bounds.Admits(rule.Count); err != nil {
			return fmt.Errorf("rule %q counts %d inside %s: %w", rule.ID, rule.Count.AtLeast, rule.Count.Within, err)
		}
		if err := r.bounds.Orders(rule.Sequence); err != nil {
			return fmt.Errorf("rule %q orders %d stages inside %s: %w",
				rule.ID, len(rule.Sequence.Stages), rule.Sequence.Within, err)
		}
		if err := r.partitioning.Admits(rule.Count); err != nil {
			return fmt.Errorf("rule %q counts across %v and the stream is keyed by %v: %w",
				rule.ID, rule.Count.GroupBy, r.partitioning.By, err)
		}
		if err := r.partitioning.Orders(rule.Sequence); err != nil {
			return fmt.Errorf("rule %q orders across %v and the stream is keyed by %v: %w",
				rule.ID, rule.Sequence.GroupBy, r.partitioning.By, err)
		}
	}
	return nil
}

// The longest window anything running keeps, widened by the skew the gateway
// admits: a window is event time and the stream is ordered by arrival.
func (r runtime) recovering(running *ruleset.Snapshot) time.Duration {
	if running == nil {
		return 0
	}
	longest := time.Duration(0)
	for _, rule := range runs(running) {
		longest = max(longest, rule.Count.Within, rule.Sequence.Within)
	}
	if longest == 0 {
		return 0
	}
	return min(longest, r.bounds.Window) + r.skew
}

// A rule admitted only because one reader holds the stream is wrong the moment
// a second one joins. A reader holding none of it decides nothing, which is
// also what a stopping one holds.
func (r runtime) owns(running *ruleset.Snapshot, held, total int32) error {
	if running == nil || total <= 0 || held <= 0 || held >= total {
		return nil
	}
	for _, rule := range runs(running) {
		group := rule.Count.GroupBy
		if rule.Sequence.Correlates() {
			group = rule.Sequence.GroupBy
		}
		if (rule.Count.Counts() || rule.Sequence.Correlates()) && !r.partitioning.Colocates(group) {
			return fmt.Errorf(
				"rule %q groups by %v, which only one reader of a stream keyed by %v can count whole, and this reader holds %d of %d partitions",
				rule.ID, group, r.partitioning.By, held, total)
		}
	}
	return nil
}

func runs(running *ruleset.Snapshot) []detection.Rule {
	var active []detection.Rule
	for program := range running.All() {
		if rule := program.Rule(); rule.Status.Runs() {
			active = append(active, rule)
		}
	}
	return active
}

func keeping(engine runtime, running *ruleset.Snapshot) (*detectionstate.Keeper, error) {
	if err := engine.validate(); err != nil {
		return nil, err
	}
	if err := engine.admits(running); err != nil {
		return nil, err
	}
	return detectionstate.NewKeeper(engine.bounds)
}
