package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

// The rules an installation starts from reach the log as its first publication,
// under the identifier this engine composed from the same tree. Reading them
// back is therefore not a rollout: the engine keeps the snapshot it started on,
// and nothing its counting rules remember is rebuilt under another one.
func TestTheFirstPublicationOfTheTreeAnEngineStartedOnIsNotARollout(t *testing.T) {
	directory := t.TempDir()
	write(t, filepath.Join(directory, "rules.yml"), oneRule)

	held := registry(t, directory)
	started := held.Current()

	programs, err := rulefile.Read(os.DirFS(directory))
	if err != nil {
		t.Fatalf("read the tree as the control plane does: %v", err)
	}
	version, err := ruleset.NewVersion(programs, nil, ruleset.Installation, time.Now().UTC(), "")
	if err != nil {
		t.Fatalf("publish the tree: %v", err)
	}

	log := rulesetLog{catalogue: ruleset.NewCatalogue()}
	apply := log.applying(quiet(), held, deployment(), whole)
	for _, record := range []*rulesetv1.Record{
		version.Record(),
		{Record: &rulesetv1.Record_Active{Active: &rulesetv1.Active{RulesetId: string(version.ID()), ActivatedBy: ruleset.Installation}}},
	} {
		if err := apply(context.Background(), recorded(t, record)); err != nil {
			t.Fatalf("apply a record of the first publication: %v", err)
		}
	}

	if active, running := log.catalogue.Active(); !running || active.ID() != started.ID() {
		t.Fatalf("the log names %v and the engine started on %s", active, started.ID())
	}
	if held.Current() != started {
		t.Fatal("the engine swapped the snapshot it started on for the same rules read off the log")
	}
}
