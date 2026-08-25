package rulefile_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
)

const checked = `schema_version: 1
rules:
  - id: ssh.failed_password_from_outside
    revision: 1
    name: Failed SSH password from an external address
    description: A password authentication over SSH failed from outside the estate.
    class: authentication
    severity: medium
    status: active
    match:
      all:
        - field: authentication.outcome
          equals: failure
        - not:
            field: authentication.network.source.ip
            starts_with: "10."
    tests:
      - name: a failure from outside
        expect: match
        severity: medium
        evidence: [authentication.outcome, authentication.network.source.ip]
        event:
          authentication.outcome: failure
          authentication.network.source.ip: 203.0.113.10
      - name: a failure from inside
        description: The false positive the rule is written to avoid.
        expect: no_match
        event:
          authentication.outcome: failure
          authentication.network.source.ip: 10.0.0.5
`

func TestTheCasesWrittenBesideARuleAreReadWithIt(t *testing.T) {
	written, err := rulefile.Parse("rules/core/ssh.yml", []byte(checked))
	if err != nil {
		t.Fatalf("a rule file that should be read was refused: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("the file holds %d rules", len(written))
	}

	cases := written[0].Cases
	if len(cases) != 2 {
		t.Fatalf("the rule carries %d cases", len(cases))
	}
	if cases[0].Name != "a failure from outside" || cases[0].Expect != detection.Matches {
		t.Errorf("the first case is %q expecting %q", cases[0].Name, cases[0].Expect)
	}
	if cases[0].Severity != detection.Medium || len(cases[0].Evidence) != 2 {
		t.Errorf("the first case expects %q and %v", cases[0].Severity, cases[0].Evidence)
	}
	if held := cases[0].Event["authentication.network.source.ip"]; held.Text() != "203.0.113.10" {
		t.Errorf("the first case carries %v as the source address", held)
	}
	if cases[1].Expect != detection.DoesNotMatch || cases[1].Description == "" {
		t.Errorf("the second case is %q and says %q", cases[1].Expect, cases[1].Description)
	}
	if written[0].Source != "rules/core/ssh.yml" {
		t.Errorf("the rule says it was written in %q", written[0].Source)
	}
}

// A rule without cases is read: whether an estate ships one is a decision, and
// the reader is not where it is made.
func TestARuleWithoutCasesIsRead(t *testing.T) {
	written, err := rulefile.Parse("rules/core/ssh.yml", []byte(rule(`{field: event_id, present: true}`)))
	if err != nil {
		t.Fatalf("a rule with no cases was refused: %v", err)
	}
	if len(written[0].Cases) != 0 {
		t.Errorf("a rule with no cases carries %d", len(written[0].Cases))
	}
}

func TestACaseTheReaderRefusesSaysWhereItWasWritten(t *testing.T) {
	cases := map[string]struct {
		part string
		says string
		body string
	}{
		"tests that are not a list": {"tests", "is not a list of cases", "    tests: a case\n"},
		"a case that is not a mapping": {"tests[0]", "a case is not a mapping",
			"    tests:\n      - a case\n"},
		"a key a case does not have": {"tests[0].expects", "is not part of a case",
			"    tests:\n      - name: a case\n        expects: match\n"},
		"an event that is not a mapping": {"tests[0].event", "an event is not a mapping",
			"    tests:\n      - name: a case\n        expect: match\n        event: an event\n"},
		"a case with no name": {"tests[0].name", "is missing",
			"    tests:\n      - expect: match\n        event: {event_id: abc}\n"},
		"two cases under one name": {"tests[1].name", "another case already is",
			"    tests:\n      - name: a case\n        expect: match\n        event: {event_id: abc}\n" +
				"      - name: a case\n        expect: no_match\n        event: {event_id: def}\n"},
		"an answer deciding does not have": {"tests[0].expect", "match or no_match",
			"    tests:\n      - name: a case\n        expect: fires\n        event: {event_id: abc}\n"},
		"a field the contract does not declare": {"tests[0].event.origin.agent", "not a field the contract declares",
			"    tests:\n      - name: a case\n        expect: match\n        event: {origin.agent: abc}\n"},
		"a value that is not a literal": {"tests[0].event.event_id", "is not text, a number or true and false",
			"    tests:\n      - name: a case\n        expect: match\n        event:\n          event_id: [a, b]\n"},
		"a field given what it cannot hold": {"tests[0].event.authentication.network.source.port", "holds number and is given",
			"    tests:\n      - name: a case\n        expect: match\n        event: {authentication.network.source.port: \"22\"}\n"},
		"a value nothing can be told from absence": {"tests[0].event.event_id", "told from carrying nothing",
			"    tests:\n      - name: a case\n        expect: match\n        event: {event_id: \"\"}\n"},
		"a severity expected of quiet": {"tests[0].severity", "only a match carries one",
			"    tests:\n      - name: a case\n        expect: no_match\n        severity: high\n        event: {event_id: abc}\n"},
	}

	for name, refused := range cases {
		t.Run(name, func(t *testing.T) {
			fault := refusal(t, rule(`{field: event_id, present: true}`)+refused.body)
			if fault.Part != refused.part {
				t.Errorf("the refusal points at %q and should point at %q: %v", fault.Part, refused.part, fault)
			}
			if !strings.Contains(fault.Reason, refused.says) {
				t.Errorf("the refusal reads %q and should say %q", fault.Reason, refused.says)
			}
			if fault.Line == 0 {
				t.Errorf("the refusal does not say where in the file it was written: %v", fault)
			}
		})
	}
}

func TestCheckingATreeRunsEveryCaseWrittenInIt(t *testing.T) {
	report, err := rulefile.Check(fstest.MapFS{
		"core/ssh.yml":     {Data: []byte(checked)},
		"core/nothing.yml": {Data: []byte(rule(`{field: event_id, present: true}`))},
	})
	if err != nil {
		t.Fatalf("a tree that should be checked was refused: %v", err)
	}

	if report.Rules != 2 || report.Cases != 2 {
		t.Errorf("the tree checked as %s", report)
	}
	if !report.Held() {
		t.Errorf("a tree whose cases hold reported %v", report.Unheld)
	}
	if len(report.Untested) != 1 || report.Untested[0] != "a.rule" {
		t.Errorf("the rules nothing was written for are %v", report.Untested)
	}
}

// A case that stops holding names the file, the rule and the case, which is what
// a person reading a failed build needs to find it.
func TestACaseThatStopsHoldingNamesWhereToLook(t *testing.T) {
	widened := strings.Replace(checked, `starts_with: "10."`, `starts_with: "198."`, 1)

	report, err := rulefile.Check(fstest.MapFS{"core/ssh.yml": {Data: []byte(widened)}})
	if err != nil {
		t.Fatalf("a tree that should be checked was refused: %v", err)
	}
	if report.Held() {
		t.Fatal("a rule that no longer answers its cases held them")
	}

	unheld := report.Unheld[0].Error()
	for _, expected := range []string{"core/ssh.yml", "ssh.failed_password_from_outside", "a failure from inside"} {
		if !strings.Contains(unheld, expected) {
			t.Errorf("the failure does not mention %q: %s", expected, unheld)
		}
	}
}

// A broken tree is refused rather than reported as cases that did not hold: a
// rule that does not compile has nothing to be checked against.
func TestATreeThatCannotBeReadIsNotCheckedAtAll(t *testing.T) {
	_, err := rulefile.Check(fstest.MapFS{
		"core/ssh.yml": {Data: []byte(strings.Replace(checked, "class: authentication", "class: network", 1))},
	})
	if err == nil {
		t.Fatal("a tree that cannot be read was checked")
	}
}
