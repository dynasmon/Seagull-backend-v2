package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
)

const recordingVariable = "SEAGULL_RECORD_STARTING_RULES"

var shippedBefore = filepath.Join("testdata", "starting")

// Every tree of rules this repository shipped is kept as the record a fresh
// installation wrote for it, which is what an installation of that release
// holds in its log. An upgrade publishes the tree of this release beside them,
// so the tree has to be admitted over every one: a shipped rule that changed
// and kept its revision fails here, where the author can still raise it. The
// same run holds this build to reading what the releases before it wrote.
func TestTheShippedRulesArePublishableOverEveryTreeShippedBefore(t *testing.T) {
	administrator, written := administer(t)
	start(t, administrator, os.DirFS(filepath.Join("..", "..", "deploy", "rules")))
	if len(written.records) == 0 || written.records[0].GetVersion() == nil {
		t.Fatal("a fresh installation published nothing from the shipped tree, so this proves nothing")
	}
	shipped := written.records[0]
	version, err := ruleset.DecodeVersion(shipped.GetVersion())
	if err != nil {
		t.Fatalf("read back what a fresh installation publishes: %v", err)
	}

	recorded, err := filepath.Glob(filepath.Join(shippedBefore, "*.pb"))
	if err != nil {
		t.Fatal(err)
	}
	held := ruleset.NewCatalogue()
	for _, name := range recorded {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := held.Read(content, false); err != nil {
			t.Fatalf("%s is not a record this build reads beside the others: %v", name, err)
		}
		if named := ruleset.ID(strings.TrimSuffix(filepath.Base(name), ".pb")); !held.Published(named) {
			t.Fatalf("%s does not hold the ruleset it is named by", name)
		}
	}

	if err := held.Admits(version); err != nil {
		t.Fatalf("the shipped rules cannot be published on an installation of a release before this one: %v", err)
	}

	if into := os.Getenv(recordingVariable); into != "" && !held.Published(version.ID()) {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(shipped)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(into, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(into, string(version.ID())+".pb"), encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := held.Apply(shipped); err != nil {
			t.Fatal(err)
		}
		t.Logf("recorded the shipped rules as %s into %s", version.ID(), into)
	}

	if !held.Published(version.ID()) {
		t.Fatalf("the shipped rules are %s, which no recording holds: record them with make record-starting-rules", version.ID())
	}
}
