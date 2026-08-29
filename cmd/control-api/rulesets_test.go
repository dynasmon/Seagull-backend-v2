package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

var published = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

// A log that keeps what it is handed, so a test can prove the whole path from a
// document to a pinned ruleset without a broker in the room.
type log struct {
	records []*rulesetv1.Record
	refuse  error
}

func (l *log) Publish(_ context.Context, record *rulesetv1.Record) error {
	if l.refuse != nil {
		return l.refuse
	}
	l.records = append(l.records, record)
	return nil
}

func administer(t *testing.T) (rulesets, *log) {
	t.Helper()

	written := &log{}
	return rulesets{catalogue: ruleset.NewCatalogue(), publisher: written}, written
}

func documents(t *testing.T) []*rulesetv1.Document {
	t.Helper()

	directory := filepath.Join("..", "..", "deploy", "rules")
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read the shipped rules: %v", err)
	}

	read := make([]*rulesetv1.Document, 0, len(entries))
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		read = append(read, &rulesetv1.Document{Name: entry.Name(), Content: content})
	}
	if len(read) == 0 {
		t.Fatal("the shipped rule tree is empty, so this proves nothing")
	}
	return read
}

func TestTheShippedRulesValidateAndTheirCasesHold(t *testing.T) {
	administrator, _ := administer(t)

	validation, report := administrator.Check(documents(t))
	if !validation.GetValid() {
		t.Fatalf("the shipped rules do not compile: %v", validation.GetFaults())
	}
	if validation.GetRulesetId() == "" || validation.GetRules() == 0 {
		t.Fatalf("a valid ruleset was described as %v", validation)
	}
	if !report.GetHeld() {
		t.Fatalf("the shipped rules have cases that do not hold: %v", report.GetUnheld())
	}
	if report.GetCases() == 0 {
		t.Error("the shipped rules carry no cases, so publishing proves nothing about them")
	}
}

// The id a validation reports is the id the ruleset is published under, so the
// thing somebody approved is the thing that can be activated.
func TestPublishingKeepsTheIdTheValidationReported(t *testing.T) {
	administrator, written := administer(t)
	held := documents(t)

	validation := administrator.Validate(held)
	answer, err := administrator.Publish(context.Background(), &rulesetv1.PublishRequest{Documents: held, Note: "first"}, "dev-engineer", published)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !answer.GetPublished() {
		t.Fatalf("the shipped rules were not published: %v", answer)
	}
	if answer.GetRulesetId() != validation.GetRulesetId() {
		t.Fatalf("validation named %s and publishing named %s", validation.GetRulesetId(), answer.GetRulesetId())
	}
	if len(written.records) != 1 {
		t.Fatalf("%d records reached the log", len(written.records))
	}

	version, ok := administrator.Version(answer.GetRulesetId())
	if !ok {
		t.Fatal("the published ruleset cannot be read back")
	}
	if version.GetPublishedBy() != "dev-engineer" || version.GetNote() != "first" {
		t.Errorf("the version was recorded as %q: %q", version.GetPublishedBy(), version.GetNote())
	}
}

func TestARulesetThatDoesNotCompileNeverReachesTheLog(t *testing.T) {
	administrator, written := administer(t)

	broken := []*rulesetv1.Document{{Name: "broken.yml", Content: []byte("schema_version: 1\nrules:\n  - id: nope\n")}}
	answer, err := administrator.Publish(context.Background(), &rulesetv1.PublishRequest{Documents: broken}, "dev-engineer", published)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if answer.GetPublished() {
		t.Fatal("a ruleset that does not compile was published")
	}
	if len(written.records) != 0 {
		t.Fatalf("%d records reached the log for a ruleset that does not compile", len(written.records))
	}

	faults := answer.GetValidation().GetFaults()
	if len(faults) == 0 {
		t.Fatal("a refusal that says nothing leaves nothing to fix")
	}
	if faults[0].GetSource() != "broken.yml" {
		t.Errorf("the fault came from %q", faults[0].GetSource())
	}
}

// A rule whose own case says it is wrong is refused where it is published, not
// discovered by an engine deciding events against it.
func TestARuleWhoseCaseDoesNotHoldNeverReachesTheLog(t *testing.T) {
	administrator, written := administer(t)

	held := []*rulesetv1.Document{{Name: "wrong.yml", Content: []byte(`schema_version: 1
rules:
  - id: ssh.session_opened
    revision: 1
    name: A session was opened
    description: Somebody authenticated successfully over ssh.
    class: authentication
    severity: medium
    status: active
    match:
      all:
        - field: authentication.outcome
          equals: success
    tests:
      - name: a success is not matched
        expect: no_match
        event:
          authentication.outcome: success
`)}}

	answer, err := administrator.Publish(context.Background(), &rulesetv1.PublishRequest{Documents: held}, "dev-engineer", published)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if answer.GetPublished() {
		t.Fatal("a rule whose case says it is wrong was published")
	}
	if answer.GetCheck().GetHeld() || len(answer.GetCheck().GetUnheld()) == 0 {
		t.Fatalf("the unheld case was not reported: %v", answer.GetCheck())
	}
	if len(written.records) != 0 {
		t.Fatalf("%d records reached the log", len(written.records))
	}
}

func TestNothingIsRememberedWhenTheLogRefusesIt(t *testing.T) {
	administrator, written := administer(t)
	written.refuse = errors.New("the backbone is unreachable")

	if _, err := administrator.Publish(context.Background(), &rulesetv1.PublishRequest{Documents: documents(t)}, "dev-engineer", published); err == nil {
		t.Fatal("a ruleset the log refused was reported as published")
	}
	if len(administrator.List().GetVersions()) != 0 {
		t.Error("a ruleset the log refused is listed as published")
	}
}

func TestActivatingWalksForwardAndBackAndOnlyOverPublishedRulesets(t *testing.T) {
	administrator, _ := administer(t)
	held := documents(t)

	first, err := administrator.Publish(context.Background(), &rulesetv1.PublishRequest{Documents: held}, "dev-engineer", published)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	if _, err := administrator.Activate(context.Background(), "0000", "", "dev-engineer", published); !errors.Is(err, control.ErrUnknownRuleset) {
		t.Fatalf("activating something nobody published answered %v", err)
	}

	activated, err := administrator.Activate(context.Background(), first.GetRulesetId(), "rolling out", "dev-engineer", published)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if activated.GetReplaced() != "" {
		t.Errorf("the first activation replaced %q", activated.GetReplaced())
	}

	listed := administrator.List()
	if listed.GetActive().GetRulesetId() != first.GetRulesetId() {
		t.Fatalf("the list names %q as active", listed.GetActive().GetRulesetId())
	}
	if len(listed.GetVersions()) != 1 || !listed.GetVersions()[0].GetActive() {
		t.Fatalf("the list describes %v", listed.GetVersions())
	}
}
