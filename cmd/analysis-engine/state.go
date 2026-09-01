package main

import (
	"fmt"

	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
)

// Where a counting rule's window is kept, and the third bridge this executable
// owns: what a rule remembers and what runs it are separate capabilities, so an
// executable is what chooses a store and bounds it.
//
// A rule the bounds could never answer stops the process. It would otherwise run
// and never fire, which is the quietest way a detection surface can be wrong,
// and an operator who narrowed the bounds is told at the moment they did it.
func keeping(bounds detectionstate.Bounds, running *ruleset.Snapshot) (*detectionstate.Keeper, error) {
	keeper, err := detectionstate.NewKeeper(bounds)
	if err != nil {
		return nil, err
	}
	if running == nil {
		return keeper, nil
	}

	for program := range running.All() {
		rule := program.Rule()
		if err := bounds.Admits(rule.Count); err != nil {
			return nil, fmt.Errorf("rule %q counts %d inside %s: %w", rule.ID, rule.Count.AtLeast, rule.Count.Within, err)
		}
	}
	return keeper, nil
}
