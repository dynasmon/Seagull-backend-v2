package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

var started = time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)

func sessionOpened(revision int, severity string) string {
	return fmt.Sprintf(`schema_version: 1
rules:
  - id: ssh.session_opened
    revision: %d
    name: A session was opened
    description: Somebody authenticated successfully over ssh.
    class: authentication
    severity: %s
    status: active
    match:
      field: authentication.outcome
      equals: success
    tests:
      - name: a success is matched
        expect: match
        event:
          authentication.outcome: success
`, revision, severity)
}

func document(name, content string) *rulesetv1.PublishRequest {
	return &rulesetv1.PublishRequest{Documents: []*rulesetv1.Document{{Name: name, Content: []byte(content)}}}
}

func tree(files map[string]string) fs.FS {
	held := fstest.MapFS{}
	for name, content := range files {
		held[name] = &fstest.MapFile{Data: []byte(content)}
	}
	return held
}

func silent() *slog.Logger { return slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)) }

func heard() (*slog.Logger, *bytes.Buffer) {
	told := &bytes.Buffer{}
	return slog.New(slog.NewJSONHandler(told, nil)), told
}

func events(t *testing.T, told *bytes.Buffer, message string) []map[string]any {
	t.Helper()

	var found []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(told.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("read a log line: %v", err)
		}
		if entry["msg"] == message {
			found = append(found, entry)
		}
	}
	return found
}

func start(t *testing.T, administrator rulesets, rules fs.FS) {
	t.Helper()

	if err := administrator.starting(context.Background(), rules, started, silent()); err != nil {
		t.Fatalf("start from the rule tree: %v", err)
	}
}

// A control plane that started again: it holds nothing but what the log gives
// back, read the way the replay reads it, and writes to the same log.
func restarted(t *testing.T, before rulesets, written *log) rulesets {
	t.Helper()

	catalogue := ruleset.NewCatalogue()
	for index, record := range written.records {
		encoded, err := proto.Marshal(record)
		if err != nil {
			t.Fatalf("encode record %d: %v", index, err)
		}
		if err := catalogue.Read(encoded, broker.Desired([]byte(written.keys[index]))); err != nil {
			t.Fatalf("replay record %d: %v", index, err)
		}
	}
	return rulesets{catalogue: catalogue, publisher: written, largest: before.largest}
}

func TestAFreshInstallationPublishesTheRulesItStartsFromAndPointsAtThem(t *testing.T) {
	administrator, written := administer(t)

	logger, told := heard()
	if err := administrator.starting(context.Background(), tree(map[string]string{"ssh.yml": sessionOpened(1, "medium")}), started, logger); err != nil {
		t.Fatalf("start from the rule tree: %v", err)
	}

	listed := administrator.List()
	if len(listed.GetVersions()) != 1 {
		t.Fatalf("%d rulesets are listed on an installation that just started", len(listed.GetVersions()))
	}
	for _, done := range []string{"starting_ruleset_published", "starting_ruleset_activated"} {
		if said := events(t, told, done); len(said) != 1 || said[0]["ruleset"] != listed.GetVersions()[0].GetId() {
			t.Errorf("%s was said as %v", done, said)
		}
	}
	first := listed.GetVersions()[0]
	if first.GetPublishedBy() != ruleset.Installation || !first.GetPublishedAt().AsTime().Equal(started) {
		t.Errorf("the starting rules were published by %q at %s", first.GetPublishedBy(), first.GetPublishedAt().AsTime())
	}
	if first.GetRules() != 1 || !first.GetActive() {
		t.Errorf("the starting rules are listed as %d rules, active=%v", first.GetRules(), first.GetActive())
	}

	active := listed.GetActive()
	if active.GetRulesetId() != first.GetId() || active.GetActivatedBy() != ruleset.Installation {
		t.Errorf("the pointer names %q, written by %q", active.GetRulesetId(), active.GetActivatedBy())
	}

	if len(written.records) != 3 {
		t.Fatalf("%d records reached the log, and a first start writes a version, a line of the trail and the pointer", len(written.records))
	}
	if written.records[0].GetVersion().GetId() != first.GetId() {
		t.Error("the pointer was written before the version it names")
	}
	if written.keys[2] != broker.ActiveKey || written.records[2].GetActive().GetRulesetId() != first.GetId() {
		t.Errorf("the last record is under %q", written.keys[2])
	}
}

// The property ADR 15's bootstrap rests on once the tree is published: what the
// control plane records is the ruleset the engine pinned from the same files,
// so nothing changes hands when the engine first reads the log.
func TestTheRulesAnInstallationPublishesAreTheRulesetItsEngineStartedOn(t *testing.T) {
	shipped := os.DirFS(filepath.Join("..", "..", "deploy", "rules"))
	programs, err := rulefile.Read(shipped)
	if err != nil {
		t.Fatalf("read the shipped rules as an engine does: %v", err)
	}
	pinned, err := ruleset.Compose(programs)
	if err != nil {
		t.Fatalf("compose the shipped rules as an engine does: %v", err)
	}
	if pinned.Rules() == 0 {
		t.Fatal("the shipped rule tree holds no rules, so this proves nothing")
	}

	administrator, _ := administer(t)
	start(t, administrator, shipped)

	if active := administrator.List().GetActive().GetRulesetId(); active != string(pinned.ID()) {
		t.Fatalf("the engine starts on %s and the control plane points at %q", pinned.ID(), active)
	}
}

// The eighth finding of the integration audit: the first publication of an
// installation redefined a rule at the revision its engine had already detected
// on, and the stored detections then meant two things under one name.
func TestAShippedRuleRepublishedAtItsRevisionAskingSomethingElseIsRefused(t *testing.T) {
	administrator, written := administer(t)
	start(t, administrator, tree(map[string]string{"ssh.yml": sessionOpened(1, "medium")}))
	recorded := len(written.records)

	redefined := &rulesetv1.PublishRequest{Documents: []*rulesetv1.Document{{Name: "ssh.yml", Content: []byte(sessionOpened(1, "critical"))}}}
	answer, err := administrator.Publish(context.Background(), redefined, "dev-engineer", published)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if answer.GetPublished() || len(written.records) != recorded {
		t.Fatal("a shipped rule was redefined at the revision an engine already ran")
	}
	faults := answer.GetValidation().GetFaults()
	if len(faults) != 1 || faults[0].GetRule() != "ssh.session_opened" || faults[0].GetPart() != "revision" {
		t.Fatalf("the refusal does not name the rule and its revision: %v", faults)
	}

	raised := &rulesetv1.PublishRequest{Documents: []*rulesetv1.Document{{Name: "ssh.yml", Content: []byte(sessionOpened(2, "critical"))}}}
	answer, err = administrator.Publish(context.Background(), raised, "dev-engineer", published)
	if err != nil {
		t.Fatalf("publish the next revision: %v", err)
	}
	if !answer.GetPublished() {
		t.Fatalf("a shipped rule changed under its next revision was refused: %v", answer.GetValidation().GetFaults())
	}
}

// Every start reads the tree again, so what was recorded once must be found
// recorded: a control plane restarted a hundred times has activated once.
func TestAnInstallationThatStartsAgainWritesNothing(t *testing.T) {
	administrator, written := administer(t)
	rules := tree(map[string]string{"ssh.yml": sessionOpened(1, "medium")})
	start(t, administrator, rules)
	recorded := len(written.records)

	again := restarted(t, administrator, written)
	logger, told := heard()
	if err := again.starting(context.Background(), rules, started.Add(time.Hour), logger); err != nil {
		t.Fatalf("start again: %v", err)
	}

	if len(written.records) != recorded {
		t.Fatalf("a second start wrote %d records", len(written.records)-recorded)
	}
	if told.Len() != 0 {
		t.Errorf("a start that did nothing reported something: %s", told)
	}
	if lines := len(again.catalogue.Activations()); lines != 1 {
		t.Errorf("the trail holds %d activations after two starts on one tree", lines)
	}
	if first := again.List().GetVersions()[0]; !first.GetPublishedAt().AsTime().Equal(started) {
		t.Errorf("starting again moved the publication to %s", first.GetPublishedAt().AsTime())
	}
}
