package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const oneRule = `schema_version: 1
rules:
  - id: authentication.failed
    revision: 1
    name: An authentication failed
    description: A rule narrow enough to be decided from one event.
    class: authentication
    severity: high
    status: active
    match:
      field: authentication.outcome
      equals: failure
`

func registry(t *testing.T, directory string) *ruleset.Registry {
	t.Helper()

	held, err := ruleset.New(ruleset.Options{
		Source:  written(directory),
		Metrics: ruleset.NewMetrics(metrics.New("test")),
		Logger:  slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatalf("read the ruleset: %v", err)
	}
	return held
}

func TestTheRulesetAProcessIsPinnedToReachesTheEngine(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "authentication.yml"), []byte(oneRule), 0o600); err != nil {
		t.Fatalf("write a rule file: %v", err)
	}

	held := registry(t, directory)
	current := rules{registry: held}.Current()
	if current == nil {
		t.Fatal("the engine was handed no ruleset")
	}
	if current.ID() != string(held.Current().ID()) {
		t.Errorf("the engine reads ruleset %q and the registry holds %q", current.ID(), held.Current().ID())
	}

	var decided []string
	for program := range current.For(eventv1.EventClass_EVENT_CLASS_AUTHENTICATION) {
		decided = append(decided, string(program.Rule().ID))
	}
	if len(decided) != 1 || decided[0] != "authentication.failed" {
		t.Errorf("the route is registered with %v", decided)
	}
}

// A process that cannot read its rules does not start, so a directory that is
// not there is a refusal rather than an engine running against nothing.
func TestARulesetThatCannotBeReadRefusesToStart(t *testing.T) {
	if _, err := written(filepath.Join(t.TempDir(), "absent"))(); err == nil {
		t.Error("a directory that is not there read as a ruleset")
	}
}

// The ruleset the local stack mounts is held to compiling, so a rule that would
// keep the engine from starting is caught here rather than by `make up`.
func TestTheRulesTheStackMountsCompile(t *testing.T) {
	programs, err := written(filepath.Join("..", "..", "deploy", "rules"))()
	if err != nil {
		t.Fatalf("the rules the local stack mounts were refused: %v", err)
	}
	if len(programs) == 0 {
		t.Error("the local stack mounts a ruleset that runs nothing")
	}
}

// Every rule this estate ships carries the cases it was written to satisfy, and
// every one of them holds. The harness reports an untested rule rather than
// refusing it, because whether to ship one is a decision; this is where the
// decision is made, and it is that we do not.
func TestTheRulesTheStackMountsHoldTheCasesWrittenWithThem(t *testing.T) {
	report, err := rulefile.Check(os.DirFS(filepath.Join("..", "..", "deploy", "rules")))
	if err != nil {
		t.Fatalf("the rules the local stack mounts were refused: %v", err)
	}

	for _, unheld := range report.Unheld {
		t.Errorf("a case the ruleset was written to satisfy does not hold: %v", unheld)
	}
	for _, untested := range report.Untested {
		t.Errorf("rule %q ships with no case written for it", untested)
	}
	if report.Cases == 0 {
		t.Errorf("the ruleset the stack mounts is checked by nothing: %s", report)
	}
	t.Logf("the ruleset the stack mounts: %s", report)
}
