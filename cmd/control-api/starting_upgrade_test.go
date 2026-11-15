package main

import (
	"context"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
)

const invalidUser = `schema_version: 1
rules:
  - id: ssh.invalid_user
    revision: 1
    name: An account nobody has was tried
    description: A session was refused for an account the host does not hold.
    class: authentication
    severity: low
    status: active
    match:
      field: authentication.outcome
      equals: failure
`

func TestAnUpgradeBringsItsRulesAndThePointerFollowsWhileItIsTheInstallations(t *testing.T) {
	administrator, written := administer(t)
	start(t, administrator, tree(map[string]string{"ssh.yml": sessionOpened(1, "medium")}))
	before := administrator.List().GetActive().GetRulesetId()

	upgraded := restarted(t, administrator, written)
	start(t, upgraded, tree(map[string]string{"ssh.yml": sessionOpened(2, "high")}))

	listed := upgraded.List()
	if len(listed.GetVersions()) != 2 {
		t.Fatalf("%d rulesets are listed after an upgrade that changed the shipped rules", len(listed.GetVersions()))
	}
	brought := listed.GetVersions()[1]
	if brought.GetId() == before || brought.GetPublishedBy() != ruleset.Installation {
		t.Fatalf("the upgrade published %q as %q", brought.GetId(), brought.GetPublishedBy())
	}
	if active := listed.GetActive(); active.GetRulesetId() != brought.GetId() || active.GetActivatedBy() != ruleset.Installation {
		t.Fatalf("the pointer names %q, written by %q", active.GetRulesetId(), active.GetActivatedBy())
	}

	trail := upgraded.catalogue.Activations()
	if len(trail) != 2 || trail[0].GetRulesetId() != before || trail[1].GetRulesetId() != brought.GetId() {
		t.Errorf("the trail does not read the first start and then the upgrade: %v", trail)
	}
}

// An upgrade brings what a release ships and decides nothing a person decided:
// what somebody activated stays, whether they wrote it or chose to stay on the
// rules of the release before.
func TestAnUpgradeLeavesTheRulesetAPersonActivated(t *testing.T) {
	for name, choose := range map[string]func(*testing.T, rulesets) string{
		"rules of their own": func(t *testing.T, administrator rulesets) string {
			answer, err := administrator.Publish(context.Background(), document("local.yml", invalidUser), "dev-engineer", published)
			if err != nil || !answer.GetPublished() {
				t.Fatalf("publish rules of their own: %v %v", err, answer.GetValidation().GetFaults())
			}
			return answer.GetRulesetId()
		},
		"the rules the installation started from": func(_ *testing.T, administrator rulesets) string {
			return administrator.List().GetActive().GetRulesetId()
		},
	} {
		t.Run(name, func(t *testing.T) {
			administrator, written := administer(t)
			start(t, administrator, tree(map[string]string{"ssh.yml": sessionOpened(1, "medium")}))

			chosen := choose(t, administrator)
			if _, err := administrator.Activate(context.Background(), chosen, "staying here", "dev-engineer", published); err != nil {
				t.Fatalf("activate: %v", err)
			}
			recorded := len(written.records)

			upgraded := restarted(t, administrator, written)
			start(t, upgraded, tree(map[string]string{"ssh.yml": sessionOpened(2, "high")}))

			active := upgraded.List().GetActive()
			if active.GetRulesetId() != chosen || active.GetActivatedBy() != "dev-engineer" {
				t.Fatalf("an upgrade moved the pointer to %q, written by %q", active.GetRulesetId(), active.GetActivatedBy())
			}
			if wrote := written.records[recorded:]; len(wrote) != 1 || wrote[0].GetVersion().GetPublishedBy() != ruleset.Installation {
				t.Fatalf("the upgrade wrote %d records, and it brings its rules as one publication", len(wrote))
			}
		})
	}
}

// A person may take the next revision of a shipped rule before a release does.
// The log already says what that revision asks, so the release's rules cannot be
// recorded beside it: the control plane says so and serves, the engine keeps what
// the pointer names, and the pair still means one thing.
func TestStartingRulesTheLogContradictsAreReportedAndNothingIsWritten(t *testing.T) {
	administrator, written := administer(t)
	start(t, administrator, tree(map[string]string{"ssh.yml": sessionOpened(1, "medium")}))
	shipped := administrator.List().GetActive().GetRulesetId()

	answer, err := administrator.Publish(context.Background(), document("local.yml", sessionOpened(2, "critical")), "dev-engineer", published)
	if err != nil || !answer.GetPublished() {
		t.Fatalf("publish the next revision: %v %v", err, answer.GetValidation().GetFaults())
	}
	recorded := len(written.records)

	upgraded := restarted(t, administrator, written)
	logger, told := heard()
	if err := upgraded.starting(context.Background(), tree(map[string]string{"ssh.yml": sessionOpened(2, "high")}), started.Add(24*time.Hour), logger); err != nil {
		t.Fatalf("a control plane whose shipped rules the log contradicts does not serve: %v", err)
	}

	if len(written.records) != recorded {
		t.Fatalf("%d records were written for rules the log contradicts", len(written.records)-recorded)
	}
	listed := upgraded.List()
	if len(listed.GetVersions()) != 2 || listed.GetActive().GetRulesetId() != shipped {
		t.Fatalf("%d rulesets are listed and %q is active", len(listed.GetVersions()), listed.GetActive().GetRulesetId())
	}

	refused := events(t, told, "starting_ruleset_refused")
	if len(refused) != 1 {
		t.Fatalf("the refusal was said %d times", len(refused))
	}
	if refused[0]["level"] != "ERROR" || refused[0]["rule"] != "ssh.session_opened" || refused[0]["revision"] != float64(2) {
		t.Errorf("the refusal does not name what an operator has to look at: %v", refused[0])
	}
}

// An installation older than this decision may hold the shipped rules as
// something a person published and never activated. They are the same ruleset,
// so they are pointed at as they stand and keep who published them first.
func TestStartingRulesAPersonAlreadyPublishedAreActivatedAndNotPublishedAgain(t *testing.T) {
	administrator, written := administer(t)
	answer, err := administrator.Publish(context.Background(), document("ssh.yml", sessionOpened(1, "medium")), "dev-engineer", published)
	if err != nil || !answer.GetPublished() {
		t.Fatalf("publish: %v %v", err, answer.GetValidation().GetFaults())
	}

	start(t, administrator, tree(map[string]string{"ssh.yml": sessionOpened(1, "medium")}))

	listed := administrator.List()
	if len(listed.GetVersions()) != 1 || listed.GetVersions()[0].GetPublishedBy() != "dev-engineer" {
		t.Fatalf("the rules are listed %d times, published by %q", len(listed.GetVersions()), listed.GetVersions()[0].GetPublishedBy())
	}
	if active := listed.GetActive(); active.GetRulesetId() != answer.GetRulesetId() || active.GetActivatedBy() != ruleset.Installation {
		t.Fatalf("the pointer names %q, written by %q", active.GetRulesetId(), active.GetActivatedBy())
	}
	if len(written.records) != 3 {
		t.Fatalf("the log holds %d records, and the start writes the activation only", len(written.records))
	}
}

// An upgrade tells its own pointer from a person's by the name it was written
// under, so that name must be one no policy can bind and no certificate can
// carry: the guard and the policy refuse a subject by the same rule.
func TestNoCallerCanBeBoundUnderTheNameOfTheInstallation(t *testing.T) {
	if _, err := authz.NewBinding("dev-admin", authz.Platform, []string{"administrator"}, nil); err != nil {
		t.Fatalf("a binding of this shape is refused for another reason, so this proves nothing: %v", err)
	}
	if _, err := authz.NewBinding(ruleset.Installation, authz.Platform, []string{"administrator"}, nil); err == nil {
		t.Fatalf("%q can be bound, so a person could be recorded as the installation", ruleset.Installation)
	}
	if authz.ValidSubject(ruleset.Installation) {
		t.Fatalf("a certificate naming %q would pass the guard", ruleset.Installation)
	}
}
