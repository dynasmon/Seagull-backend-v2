package main

import (
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
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
