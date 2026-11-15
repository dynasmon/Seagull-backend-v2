package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

const contradictsItsCase = `schema_version: 1
rules:
  - id: ssh.session_opened
    revision: 1
    name: A session was opened
    description: Somebody authenticated successfully over ssh.
    class: authentication
    severity: medium
    status: active
    match:
      field: authentication.outcome
      equals: success
    tests:
      - name: a success is not matched
        expect: no_match
        event:
          authentication.outcome: success
`

type unableToActivate struct{ *log }

func (unableToActivate) Activate(context.Context, string, *rulesetv1.Active) error {
	return errors.New("the backbone went away")
}

// What an engine would run from this tree could not be recorded, and a control
// plane that served anyway would leave the installation as the audit found it.
func TestAControlPlaneThatCannotRecordItsStartingRulesDoesNotStart(t *testing.T) {
	for name, rules := range map[string]fs.FS{
		"a tree that is not there":            os.DirFS(filepath.Join(t.TempDir(), "absent")),
		"a rule that does not compile":        tree(map[string]string{"broken.yml": "schema_version: 1\nrules:\n  - id: nope\n"}),
		"a rule whose own case does not hold": tree(map[string]string{"wrong.yml": contradictsItsCase}),
		"rules heavier than the log carries":  tree(map[string]string{"allowlists.yml": string(allowlistedFiveTimes()[0].GetContent())}),
	} {
		t.Run(name, func(t *testing.T) {
			administrator, written := administer(t)

			if err := administrator.starting(context.Background(), rules, started, silent()); err == nil {
				t.Fatal("the control plane started")
			}
			if len(written.records) != 0 || len(administrator.List().GetVersions()) != 0 {
				t.Fatalf("%d records reached the log and %d rulesets are listed", len(written.records), len(administrator.List().GetVersions()))
			}
		})
	}
}

func TestStartingRulesTheLogRefusesAreNotRemembered(t *testing.T) {
	administrator, written := administer(t)
	written.refuse = errors.New("the backbone is unreachable")

	if err := administrator.starting(context.Background(), tree(map[string]string{"ssh.yml": sessionOpened(1, "medium")}), started, silent()); err == nil {
		t.Fatal("a control plane whose log refused its starting rules started")
	}
	if listed := administrator.List(); len(listed.GetVersions()) != 0 || listed.GetActive() != nil {
		t.Fatalf("rules the log refused are listed: %v", listed)
	}
}

// The publication and the activation are two writes, so a start can end between
// them. The next one finds the rules published and nothing pointing at them, and
// finishes rather than publishing again.
func TestAStartThatStoppedAfterPublishingIsFinishedByTheNext(t *testing.T) {
	administrator, written := administer(t)
	rules := tree(map[string]string{"ssh.yml": sessionOpened(1, "medium")})

	administrator.publisher = unableToActivate{written}
	if err := administrator.starting(context.Background(), rules, started, silent()); err == nil {
		t.Fatal("a start whose activation the log refused was reported as done")
	}
	if len(written.records) != 1 || written.records[0].GetVersion() == nil {
		t.Fatalf("%d records reached the log before the start stopped", len(written.records))
	}

	next := restarted(t, administrator, written)
	start(t, next, rules)

	listed := next.List()
	if len(listed.GetVersions()) != 1 || listed.GetActive().GetRulesetId() != listed.GetVersions()[0].GetId() {
		t.Fatalf("%d rulesets are listed and %q is active", len(listed.GetVersions()), listed.GetActive().GetRulesetId())
	}
	if len(written.records) != 3 {
		t.Fatalf("the log holds %d records, and finishing writes the activation only", len(written.records))
	}
}

// An empty ruleset that was activated would be followed by every engine, which
// would then detect nothing. A control plane given no rules has nothing to
// record, so it says so and leaves the log and the pointer as they were.
func TestAnInstallationGivenNoRulesPublishesNothing(t *testing.T) {
	for name, installed := range map[string]func(*testing.T) (rulesets, *log){
		"on its first start": administer,
		"on a start after one that had rules": func(t *testing.T) (rulesets, *log) {
			administrator, written := administer(t)
			start(t, administrator, tree(map[string]string{"ssh.yml": sessionOpened(1, "medium")}))
			return restarted(t, administrator, written), written
		},
	} {
		t.Run(name, func(t *testing.T) {
			administrator, written := installed(t)
			recorded, running := len(written.records), administrator.List().GetActive().GetRulesetId()

			logger, told := heard()
			if err := administrator.starting(context.Background(), tree(nil), started.Add(time.Hour), logger); err != nil {
				t.Fatalf("a control plane given no rules does not serve: %v", err)
			}

			if len(written.records) != recorded {
				t.Fatalf("%d records were written for a tree holding no rules", len(written.records)-recorded)
			}
			if active := administrator.List().GetActive().GetRulesetId(); active != running {
				t.Fatalf("the pointer moved from %q to %q", running, active)
			}
			if said := events(t, told, "starting_ruleset_empty"); len(said) != 1 || said[0]["level"] != "WARN" {
				t.Errorf("a tree holding no rules was passed over in silence: %v", said)
			}
		})
	}
}
