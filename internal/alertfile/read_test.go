package alertfile_test

import (
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/alertfile"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const document = `schema_version: 1

defaults:
  key: [rule, agent]
  window: 15m
  cooldown: 0s

rules:
  - id: ssh.failed_password_from_outside
    key: [rule, agent, "evidence:authentication.source.ip"]
    window: 1h
    cooldown: 30m

suppressions:
  - rule: ssh.failed_password_from_outside
    when:
      agent: [scanner-01, scanner-02]
    reason: our own credentialed scanner
    until: 2026-12-31T00:00:00Z
`

func read(t *testing.T, body string) (*alert.Tuning, error) {
	t.Helper()
	return alertfile.Read("alerting.yml", []byte(body))
}

func must(t *testing.T, body string) *alert.Tuning {
	t.Helper()
	tuning, err := read(t, body)
	if err != nil {
		t.Fatalf("read the document: %v", err)
	}
	return tuning
}

func detection(rule, agent, source string) *detectionv1.Detection {
	return &detectionv1.Detection{
		DetectionId: "a-detection",
		Rule:        &detectionv1.Rule{Id: rule, Revision: 1},
		Severity:    detectionv1.Severity_SEVERITY_MEDIUM,
		Origin:      &eventv1.Origin{TenantId: "acme", AgentId: agent},
		Evidence:    []*detectionv1.Evidence{{Field: "authentication.source.ip", Held: source}},
	}
}

func TestADocumentCompilesIntoTheFoldsAndSuppressionsItDeclares(t *testing.T) {
	tuning := must(t, document)

	if tuning.Rules() != 1 || tuning.Suppressions() != 1 {
		t.Fatalf("the document compiled to %d folds and %d suppressions", tuning.Rules(), tuning.Suppressions())
	}

	declared := tuning.Fold("ssh.failed_password_from_outside")
	if declared.Window != time.Hour || declared.Cooldown != 30*time.Minute {
		t.Errorf("the declared rule folds on %s / %s", declared.Window, declared.Cooldown)
	}
	if len(declared.Keyed) != 3 {
		t.Errorf("the declared key has %d parts", len(declared.Keyed))
	}

	fallback := tuning.Fold("anything.else")
	if fallback.Window != 15*time.Minute || fallback.Cooldown != 0 {
		t.Errorf("an undeclared rule folds on %s / %s", fallback.Window, fallback.Cooldown)
	}
}

func TestADocumentWithNoDefaultsStillFoldsAndNeverCoolsDown(t *testing.T) {
	tuning := must(t, "schema_version: 1\n")

	fold := tuning.Fold("anything")
	if fold.Window != alertfile.Defaults.Window {
		t.Errorf("the built-in window is %s", fold.Window)
	}
	if fold.Cooldown != 0 {
		t.Errorf("the built-in cooldown is %s, and silence should never be the default", fold.Cooldown)
	}
	if len(fold.Keyed) != 2 {
		t.Errorf("the built-in key has %d parts", len(fold.Keyed))
	}
}

func TestASuppressionReadFromTheDocumentHidesExactlyWhatItNames(t *testing.T) {
	tuning := must(t, document)
	before := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)

	hidden, suppressed := tuning.Suppressed(detection("ssh.failed_password_from_outside", "scanner-01", "203.0.113.10"), before)
	if !suppressed {
		t.Fatal("the scanner was not suppressed")
	}
	if hidden.Reason != "our own credentialed scanner" {
		t.Errorf("it was suppressed for %q", hidden.Reason)
	}

	if _, suppressed := tuning.Suppressed(detection("ssh.failed_password_from_outside", "web-01", "203.0.113.10"), before); suppressed {
		t.Error("an agent the suppression does not name was suppressed")
	}
	if _, suppressed := tuning.Suppressed(detection("some.other.rule", "scanner-01", "203.0.113.10"), before); suppressed {
		t.Error("a rule the suppression does not name was suppressed")
	}

	after := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, suppressed := tuning.Suppressed(detection("ssh.failed_password_from_outside", "scanner-01", "203.0.113.10"), after); suppressed {
		t.Error("an expired suppression is still hiding activity")
	}
}

func TestAMisspeltKeyIsRefusedRatherThanReadAsNothing(t *testing.T) {
	for name, body := range map[string]string{
		"an unread top-level key":           "schema_version: 1\nsupressions: []\n",
		"an unread fold key":                "schema_version: 1\ndefaults:\n  windows: 15m\n",
		"an unread suppression":             "schema_version: 1\nsuppressions:\n  - rule: r\n    reason: because\n    whn: {}\n",
		"a part nobody declares":            "schema_version: 1\ndefaults:\n  key: [rule, hostname]\n",
		"a key without the rule":            "schema_version: 1\ndefaults:\n  key: [agent]\n",
		"a suppression with no reason":      "schema_version: 1\nsuppressions:\n  - rule: r\n",
		"a negative window":                 "schema_version: 1\ndefaults:\n  window: -5m\n",
		"a window that is not one":          "schema_version: 1\ndefaults:\n  window: soon\n",
		"an until that is not an instant":   "schema_version: 1\nsuppressions:\n  - rule: r\n    reason: because\n    until: next tuesday\n",
		"an empty selector list":            "schema_version: 1\nsuppressions:\n  - reason: because\n    when:\n      agent: []\n",
		"a schema this build does not read": "schema_version: 2\n",
		"no schema at all":                  "defaults:\n  window: 15m\n",
	} {
		if _, err := read(t, body); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestAFaultSaysWhereInTheDocumentItIs(t *testing.T) {
	_, err := read(t, "schema_version: 1\ndefaults:\n  key: [rule, hostname]\n")
	if err == nil {
		t.Fatal("an undeclared key part was accepted")
	}

	fault, ok := err.(*alertfile.Fault)
	if !ok {
		t.Fatalf("the refusal is a %T and not a fault", err)
	}
	if fault.Source != "alerting.yml" || fault.Line == 0 {
		t.Errorf("the fault points at %s:%d", fault.Source, fault.Line)
	}
	if !strings.Contains(fault.Error(), "hostname") {
		t.Errorf("the fault does not name what is wrong: %s", fault)
	}
}

func TestTwoFoldsForOneRuleAreRefused(t *testing.T) {
	_, err := read(t, "schema_version: 1\nrules:\n  - id: r\n    window: 1m\n  - id: r\n    window: 2m\n")
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a rule folded twice produced %v", err)
	}
}
