package rulefile_test

import (
	"reflect"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
)

const shaped = `schema_version: 1
rules:
  - id: authentication.failed_from_outside
    revision: 3
    name: A failed password from outside
    description: A password failed for a session from outside the estate.
    class: authentication
    severity: medium
    status: draft
    technique:
      tactic: credential_access
      id: T1110.001
      name: "Brute Force: Password Guessing"
    false_positives: An administrator mistyping a password.
    response: Confirm the account is expected to be reachable from outside.
    source:
      catalogue: sigma
      identifier: 4b6a3a1e-6d61-4d0f-9f39-2b3f1b7c4a01
    tags: [ssh, credential_access]
    references:
      - https://attack.mitre.org/techniques/T1110/001/
    count:
      at_least: 20
      within: 1m
      group_by: [authentication.network.source.ip]
    match:
      all:
        - field: authentication.outcome
          equals: failure
        - field: authentication.service.protocol
          one_of: [ssh, rdp]
        - field: authentication.network.source.port
          above: 1024
        - field: authentication.user.name
          present: true
        - not:
            any:
              - field: authentication.network.source.ip
                starts_with: "10."
              - field: authentication.user.domain
                contains: corp
  - id: authentication.guessing_that_succeeded
    revision: 1
    name: Password guessing that succeeded
    description: A failure and then a success from one address.
    class: authentication
    severity: critical
    status: active
    sequence:
      within: 5m
      group_by: [authentication.network.source.ip]
      stages:
        - name: a failed password
          match:
            field: authentication.outcome
            equals: failure
        - name: one that was accepted
          match:
            field: authentication.outcome
            equals: success
`

func rulesIn(t *testing.T, document []byte) []detection.Rule {
	t.Helper()

	written, err := rulefile.Parse("rules.yml", document)
	if err != nil {
		t.Fatalf("the rules were refused: %v", err)
	}

	rules := make([]detection.Rule, 0, len(written))
	for _, one := range written {
		rules = append(rules, one.Program.Rule())
	}
	return rules
}

// A rule written back out and read again is the same rule, which is what lets a
// translation from another rule language land as a document somebody reviews
// rather than as a second way into the engine.
func TestARuleWrittenBackOutIsReadAsTheSameRule(t *testing.T) {
	rules := rulesIn(t, []byte(shaped))

	document, err := rulefile.Write(rules)
	if err != nil {
		t.Fatalf("the rules could not be written: %v", err)
	}
	if got := rulesIn(t, document); !reflect.DeepEqual(got, rules) {
		t.Errorf("the rules came back as\n%+v\nrather than\n%+v", got, rules)
	}
}

func TestWritingRefusesARuleThatMatchesNothing(t *testing.T) {
	if _, err := rulefile.Write([]detection.Rule{{ID: "a.rule"}}); err == nil {
		t.Error("a rule carrying no match was written to a file")
	}
}
