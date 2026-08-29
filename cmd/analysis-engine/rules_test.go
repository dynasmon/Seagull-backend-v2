package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

func write(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write a rule file: %v", err)
	}
}

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

const otherRule = `schema_version: 1
rules:
  - id: authentication.succeeded
    revision: 1
    name: An authentication succeeded
    description: A second rule, so a published ruleset differs from the shipped one.
    class: authentication
    severity: low
    status: active
    match:
      field: authentication.outcome
      equals: success
`

func recorded(t *testing.T, record *rulesetv1.Record) []broker.Record {
	t.Helper()

	encoded, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode a ruleset record: %v", err)
	}
	return []broker.Record{{Partition: 0, Offset: 0, Key: []byte("k"), Value: encoded}}
}

func publishedVersion(t *testing.T, document string) *ruleset.Version {
	t.Helper()

	read, err := rulefile.Parse("published.yml", []byte(document))
	if err != nil {
		t.Fatalf("read a rule: %v", err)
	}

	programs := make([]*detection.Program, 0, len(read))
	for _, rule := range read {
		programs = append(programs, rule.Program)
	}
	version, err := ruleset.NewVersion(programs, nil, "dev-engineer", time.Now().UTC(), "")
	if err != nil {
		t.Fatalf("publish a version: %v", err)
	}
	return version
}

// The rule tree the engine ships with is what it runs until the control plane
// has published something, so an engine that cannot reach a control plane still
// detects rather than starting with nothing.
func TestTheShippedTreeRunsUntilARulesetIsPublished(t *testing.T) {
	directory := t.TempDir()
	write(t, filepath.Join(directory, "rules.yml"), oneRule)

	held := registry(t, directory)
	shipped := held.Current().ID()

	log := rulesetLog{catalogue: ruleset.NewCatalogue()}
	apply := log.applying(quiet(), held)

	version := publishedVersion(t, otherRule)
	if err := apply(context.Background(), recorded(t, version.Record())); err != nil {
		t.Fatalf("apply a published version: %v", err)
	}
	if held.Current().ID() != shipped {
		t.Fatal("publishing a ruleset started running it without anybody activating it")
	}

	activation := &rulesetv1.Record{Record: &rulesetv1.Record_Active{
		Active: &rulesetv1.Active{RulesetId: string(version.ID()), ActivatedBy: "dev-engineer"},
	}}
	if err := apply(context.Background(), recorded(t, activation)); err != nil {
		t.Fatalf("apply an activation: %v", err)
	}
	if held.Current().ID() != version.ID() {
		t.Fatalf("the engine runs %s and was told to run %s", held.Current().ID(), version.ID())
	}
}

func TestARulesetRecordTheEngineCannotReadLeavesItRunningWhatItHad(t *testing.T) {
	directory := t.TempDir()
	write(t, filepath.Join(directory, "rules.yml"), oneRule)

	held := registry(t, directory)
	shipped := held.Current().ID()

	log := rulesetLog{catalogue: ruleset.NewCatalogue()}
	apply := log.applying(quiet(), held)

	if err := apply(context.Background(), []broker.Record{{Value: []byte{0xff, 0xfe}}}); err != nil {
		t.Fatalf("an unreadable record ended the replay: %v", err)
	}
	if held.Current().ID() != shipped {
		t.Fatal("an unreadable record changed what the engine runs")
	}
}

func TestAnActivationForARulesetTheEngineHasNotSeenChangesNothing(t *testing.T) {
	directory := t.TempDir()
	write(t, filepath.Join(directory, "rules.yml"), oneRule)

	held := registry(t, directory)
	shipped := held.Current().ID()

	log := rulesetLog{catalogue: ruleset.NewCatalogue()}
	apply := log.applying(quiet(), held)

	activation := &rulesetv1.Record{Record: &rulesetv1.Record_Active{
		Active: &rulesetv1.Active{RulesetId: "0000000000000000", ActivatedBy: "dev-engineer"},
	}}
	if err := apply(context.Background(), recorded(t, activation)); err != nil {
		t.Fatalf("apply an activation: %v", err)
	}
	if held.Current().ID() != shipped {
		t.Fatal("a pointer at a ruleset nobody published changed what the engine runs")
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)) }
