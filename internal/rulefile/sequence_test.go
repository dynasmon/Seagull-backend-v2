package rulefile_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
)

const told = `
schema_version: 1
rules:
  - id: ssh.password_guessing_that_succeeded
    revision: 1
    name: SSH password guessing that succeeded
    description: A failed password from an address, then one that was accepted from the same address.
    class: authentication
    severity: critical
    status: active
    sequence:
      within: 5m
      group_by: [authentication.network.source.ip, origin.agent_id]
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

func ordering(t *testing.T, document string) detection.Rule {
	t.Helper()

	written, err := rulefile.Parse("ordering.yml", []byte(document))
	if err != nil {
		t.Fatalf("a rule file that should be read was refused: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("the file holds %d rules", len(written))
	}
	return written[0].Program.Rule()
}

func TestARuleFileWritesASequence(t *testing.T) {
	sequence := ordering(t, told).Sequence

	if !sequence.Correlates() {
		t.Fatal("a rule written with a sequence read back without one")
	}
	if sequence.Within != 5*time.Minute {
		t.Errorf("the window reads as %s", sequence.Within)
	}
	if len(sequence.Stages) != 2 {
		t.Fatalf("the story reads as %d stages", len(sequence.Stages))
	}
	if sequence.Stages[0].Name != "a failed password" {
		t.Errorf("the first stage reads as %q", sequence.Stages[0].Name)
	}
	if sequence.Stages[1].Match == nil {
		t.Error("the second stage read back with no match")
	}
	if len(sequence.GroupBy) != 2 || sequence.GroupBy[0] != "authentication.network.source.ip" {
		t.Errorf("the story is grouped by %v", sequence.GroupBy)
	}
}

// A refusal points at the line and column the mistake was written on, so an
// author is told where rather than that.
func TestAWrittenSequenceIsRefusedWhereItWasWritten(t *testing.T) {
	for _, refused := range []struct {
		name    string
		part    string
		written string
	}{
		{"a window that is not one", "sequence.within", strings.Replace(told, "within: 5m", "within: soon", 1)},
		{"a window a rule may not remember for", "sequence.within", strings.Replace(told, "within: 5m", "within: 48h", 1)},
		{"a story of one stage", "sequence.stages", strings.Replace(told, `        - name: one that was accepted
          match:
            field: authentication.outcome
            equals: success
`, "", 1)},
		{"a stage with no name", "sequence.stages[1].name", strings.Replace(told, "- name: one that was accepted", "- name: \"\"", 1)},
		{"a stage naming a field the contract does not declare", "sequence.stages[0].match.authentication.nothing",
			strings.Replace(told, "field: authentication.outcome\n            equals: failure", "field: authentication.nothing\n            equals: failure", 1)},
		{"something that is not part of a stage", "sequence.stages[0].after",
			strings.Replace(told, "        - name: a failed password", "        - name: a failed password\n          after: nothing", 1)},
		{"something that is not part of a sequence", "sequence.min_events",
			strings.Replace(told, "      within: 5m", "      within: 5m\n      min_events: 10", 1)},
		{"a sequence beside a match", "sequence",
			told + "    match:\n      field: authentication.outcome\n      equals: failure\n"},
	} {
		t.Run(refused.name, func(t *testing.T) {
			_, err := rulefile.Parse("ordering.yml", []byte(refused.written))

			var fault *rulefile.Fault
			if !errors.As(err, &fault) {
				t.Fatalf("the file was read, or refused as %v", err)
			}
			if fault.Part != refused.part {
				t.Errorf("the refusal names %q and should name %q: %s", fault.Part, refused.part, fault.Reason)
			}
			if fault.Line == 0 {
				t.Error("the refusal points at no line")
			}
		})
	}
}
