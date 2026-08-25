package rulefile_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const written = `schema_version: 1
rules:
  - id: ssh.failed_password_from_outside
    revision: 2
    name: Failed SSH password from an external address
    description: A password authentication over SSH failed from outside the estate.
    class: authentication
    severity: medium
    status: active
    technique:
      tactic: credential_access
      id: T1110.001
      name: "Brute Force: Password Guessing"
    false_positives: An administrator mistyping a password from a home connection.
    response: Check for a pattern from the same address.
    source:
      catalogue: sigma
      identifier: 5013fd8a-56f1-4d5c-9f1d-4c9d0a1f3b77
    tags: [ssh, credential_access]
    references:
      - https://attack.mitre.org/techniques/T1110/001/
    match:
      all:
        - field: authentication.outcome
          equals: failure
        - field: authentication.network.source.port
          at_least: 1024
        - field: authentication.user.name
          one_of: [root, admin]
        - not:
            field: authentication.network.source.ip
            starts_with: "10."
`

func TestARuleFileParsesIntoTheRuleItWrites(t *testing.T) {
	programs, err := rulefile.Parse("rules/core/ssh.yml", []byte(written))
	if err != nil {
		t.Fatalf("a rule file that should be read was refused: %v", err)
	}
	if len(programs) != 1 {
		t.Fatalf("the file holds %d rules", len(programs))
	}

	asked := detection.Rule{
		ID:          "ssh.failed_password_from_outside",
		Revision:    2,
		Name:        "Failed SSH password from an external address",
		Description: "A password authentication over SSH failed from outside the estate.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.All{Terms: []detection.Expression{
			detection.Predicate{
				Field:    "authentication.outcome",
				Operator: detection.Equals,
				Values:   []detection.Value{detection.TextValue("failure")},
			},
			detection.Predicate{
				Field:    "authentication.network.source.port",
				Operator: detection.AtLeast,
				Values:   []detection.Value{detection.NumberValue(1024)},
			},
			detection.Predicate{
				Field:    "authentication.user.name",
				Operator: detection.OneOf,
				Values:   []detection.Value{detection.TextValue("root"), detection.TextValue("admin")},
			},
			detection.Not{Term: detection.Predicate{
				Field:    "authentication.network.source.ip",
				Operator: detection.StartsWith,
				Values:   []detection.Value{detection.TextValue("10.")},
			}},
		}},
		Severity: detection.Medium,
		Status:   detection.Active,
		Technique: detection.Technique{
			Tactic: "credential_access",
			ID:     "T1110.001",
			Name:   "Brute Force: Password Guessing",
		},
		FalsePositives: "An administrator mistyping a password from a home connection.",
		Response:       "Check for a pattern from the same address.",
		Source: detection.Source{
			Catalogue:  "sigma",
			Identifier: "5013fd8a-56f1-4d5c-9f1d-4c9d0a1f3b77",
		},
		Tags:       []string{"ssh", "credential_access"},
		References: []string{"https://attack.mitre.org/techniques/T1110/001/"},
	}

	if read := programs[0].Rule(); !reflect.DeepEqual(read, asked) {
		t.Errorf("the file was read as\n%#v\nand should have been read as\n%#v", read, asked)
	}
}

// A literal is typed the way the file wrote it, so a rule can say that a text
// field holds the characters `22` and that a numeric one holds the number.
func TestALiteralKeepsTheTypeItWasWrittenAs(t *testing.T) {
	programs, err := rulefile.Parse("rules/core/ssh.yml", []byte(rule(`
      all:
        - field: authentication.network.source.port
          equals: 22
        - field: authentication.user.uid
          equals: "22"
        - field: authentication.user.name
          present: true`)))
	if err != nil {
		t.Fatalf("a rule file that should be read was refused: %v", err)
	}

	const asked = `(authentication.network.source.port equals 22 and ` +
		`authentication.user.uid equals "22" and ` +
		`authentication.user.name present)`
	if compiled := programs[0].String(); compiled != asked {
		t.Errorf("the rule compiled to\n%s\nand should have compiled to\n%s", compiled, asked)
	}
}

func TestARuleFileTheReaderRefusesSaysWhy(t *testing.T) {
	cases := map[string]struct {
		part   string
		says   string
		source string
	}{
		"a file that is not a mapping": {"", "is not a mapping", "- a list of something\n"},
		"a file that does not say its layout": {"schema_version", "is missing", `rules: []
`},
		"a file written for another layout": {"schema_version", "this build reads 1", `schema_version: 7
rules: []
`},
		"a file that holds no rules": {"rules", "is missing", `schema_version: 1
`},
		"a file whose rules are not a list": {"rules", "is not a list of rules", `schema_version: 1
rules:
  id: a.rule
`},
		"a key a rule file does not have": {"packs", "is not part of a rule file", `schema_version: 1
packs: [core]
rules: []
`},
		"a key a rule does not have":      {"sevrity", "is not part of a rule", rule(`{field: event_id, present: true}`) + "    sevrity: high\n"},
		"a revision that is not a number": {"revision", "is not a whole number", strings.Replace(rule(`{field: event_id, present: true}`), "revision: 1", `revision: "one"`, 1)},
		"a name that is not text":         {"name", "is not text", strings.Replace(rule(`{field: event_id, present: true}`), "name: A name", "name: [a, name]", 1)},
		"a class the contract does not declare": {"class", "written for one of authentication",
			strings.Replace(rule(`{field: event_id, present: true}`), "class: authentication", "class: network", 1)},
		"a technique that is not a mapping": {"technique", "is not a mapping", rule(`{field: event_id, present: true}`) + "    technique: T1110\n"},
		"a term that is not a mapping":      {"match", "is not a mapping", rule(`always`)},
		"a list of terms that is not one":   {"match.all", "is not a list of terms", rule("\n      all: {field: event_id, present: true}")},
		"a term beside another":             {"match", "and a term says one thing", rule("\n      all: [{field: event_id, present: true}]\n      any: [{field: event_id, present: true}]")},
		"a term with nothing that names it": {"match", "neither a question about a field", rule(`{equals: root}`)},
		"a question with no field":          {"match.field", "is missing", rule("{field: , equals: root}")},
		"a question that asks nothing":      {"match.authentication.user.name", "is asked nothing", rule(`{field: authentication.user.name}`)},
		"a question that asks two things": {"match.authentication.user.name", "asks one thing",
			rule(`{field: authentication.user.name, equals: root, contains: oo}`)},
		"a question that is not one": {"match.authentication.user.name", "which is not an operator",
			rule(`{field: authentication.user.name, matches: "^root$"}`)},
		"a field the contract does not declare": {"match.authentication.user.nam", "not a field the contract declares",
			rule(`{field: authentication.user.nam, equals: root}`)},
		"a list where one value is expected": {"match.authentication.user.name", "is not text, a number or true and false",
			rule(`{field: authentication.user.name, equals: [root, admin]}`)},
		"one value where a list is expected": {"match.authentication.user.name", "reads a list of values",
			rule(`{field: authentication.user.name, one_of: root}`)},
		"a field asked not to be there": {"match.authentication.user.name", "put the question under `not`",
			rule(`{field: authentication.user.name, present: false}`)},
		"a number the field cannot hold": {"match.authentication.network.source.port", "whole numbers from 0 to 4294967295",
			rule(`{field: authentication.network.source.port, equals: -1}`)},
		"a rule that can never match": {"match.all", "which nothing satisfies", rule(`
      all:
        - {field: authentication.user.name, equals: root}
        - {field: authentication.user.name, equals: admin}`)},
		"a source that is not a mapping": {"source", "is not a mapping",
			rule(`{field: event_id, present: true}`) + "    source: sigma\n"},
		"a key a source does not have": {"source.author", "is not part of a source",
			rule(`{field: event_id, present: true}`) + "    source:\n      catalogue: sigma\n      author: somebody\n"},
		"a catalogue that is not text": {"source.catalogue", "is not text",
			rule(`{field: event_id, present: true}`) + "    source:\n      catalogue: [sigma]\n"},
		"tags that are not a list": {"tags", "is not a list",
			rule(`{field: event_id, present: true}`) + "    tags: ssh\n"},
		"a tag that is not text": {"tags[1]", "is not text",
			rule(`{field: event_id, present: true}`) + "    tags: [ssh, 22]\n"},
		"references that are not a list": {"references", "is not a list",
			rule(`{field: event_id, present: true}`) + "    references: https://example.test/\n"},
		"a tag the domain refuses": {"tags[0]", "lowercase words",
			rule(`{field: event_id, present: true}`) + "    tags: [\"Privilege Escalation\"]\n"},
		"a reference the domain refuses": {"references[0]", "http or https link",
			rule(`{field: event_id, present: true}`) + "    references: [the runbook in the wiki]\n"},
	}

	for name, broken := range cases {
		t.Run(name, func(t *testing.T) {
			fault := refusal(t, broken.source)
			if fault.Part != broken.part {
				t.Errorf("the refusal points at %q and should point at %q: %v", fault.Part, broken.part, fault)
			}
			if !strings.Contains(fault.Reason, broken.says) {
				t.Errorf("the refusal reads %q and should say %q", fault.Reason, broken.says)
			}
			if fault.Source != "rules/core/ssh.yml" {
				t.Errorf("the refusal names %q as the file", fault.Source)
			}
		})
	}
}

// What the domain refused is kept underneath what the file says about where it
// was written, so a control plane can act on either.
func TestARefusalFromTheDomainKeepsItsOwnType(t *testing.T) {
	fault := refusal(t, rule(`{field: authentication.user.nam, equals: root}`))

	var violation *detection.Violation
	if !errors.As(error(fault), &violation) {
		t.Fatalf("the refusal is a %T and does not carry what the domain said", fault)
	}
	if violation.Rule != "a.rule" || violation.Part != "match.authentication.user.nam" {
		t.Errorf("the refusal underneath names rule %q part %q", violation.Rule, violation.Part)
	}
}

func TestARefusalSaysWhereInTheFileItWasWritten(t *testing.T) {
	fault := refusal(t, `schema_version: 1
rules:
  - id: a.rule
    revision: 1
    name: A name
    description: A description.
    class: authentication
    severity: medium
    status: active
    match:
      field: authentication.user.nam
      equals: root
`)

	if fault.Line != 11 || fault.Column != 14 {
		t.Errorf("the refusal points at %d:%d and the field is written at 11:14", fault.Line, fault.Column)
	}
	if !strings.HasPrefix(fault.Error(), "rules/core/ssh.yml:11:14: rule \"a.rule\": match.authentication.user.nam ") {
		t.Errorf("the refusal reads %q", fault.Error())
	}
}

func TestTwoRulesInAFileCannotShareAnId(t *testing.T) {
	fault := refusal(t, `schema_version: 1
rules:
  - id: a.rule
    revision: 1
    name: A name
    description: A description.
    class: authentication
    severity: medium
    status: active
    match: {field: event_id, present: true}
  - id: a.rule
    revision: 2
    name: Another name
    description: Another description.
    class: authentication
    severity: low
    status: active
    match: {field: event_id, present: true}
`)

	if fault.Part != "id" || !strings.Contains(fault.Reason, "is also the id of a rule in rules/core/ssh.yml") {
		t.Errorf("the refusal reads %v", fault)
	}
	if fault.Line != 11 {
		t.Errorf("the refusal points at line %d and the second rule is written at 11", fault.Line)
	}
}

func TestAFileWithNothingInItHoldsNoRules(t *testing.T) {
	for _, source := range []string{"", "\n", "# nothing but a comment\n"} {
		programs, err := rulefile.Parse("rules/core/ssh.yml", []byte(source))
		if err != nil {
			t.Errorf("an empty file was refused: %v", err)
		}
		if len(programs) != 0 {
			t.Errorf("an empty file held %d rules", len(programs))
		}
	}
}

// One file, one document: a second one after it would be read by nothing.
func TestAFileHoldsOneDocument(t *testing.T) {
	fault := refusal(t, "schema_version: 1\nrules: []\n---\nschema_version: 1\nrules: []\n")
	if !strings.Contains(fault.Reason, "more than one document") {
		t.Errorf("the refusal reads %v", fault)
	}
}

func rule(match string) string {
	return `schema_version: 1
rules:
  - id: a.rule
    revision: 1
    name: A name
    description: A description.
    class: authentication
    severity: medium
    status: active
    match: ` + match + "\n"
}

func refusal(t *testing.T, source string) *rulefile.Fault {
	t.Helper()

	programs, err := rulefile.Parse("rules/core/ssh.yml", []byte(source))
	if err == nil {
		t.Fatalf("a rule file that should have been refused was read into %d rules", len(programs))
	}

	var fault *rulefile.Fault
	if !errors.As(err, &fault) {
		t.Fatalf("the refusal is a %T and should say where in the file it was written: %v", err, err)
	}
	return fault
}
