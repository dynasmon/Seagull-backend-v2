package rulefile_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
)

const counted = `
schema_version: 1
rules:
  - id: ssh.repeated_failed_password
    revision: 1
    name: Repeated failed SSH passwords from one address
    description: Twenty password failures from one address against one agent inside a minute.
    class: authentication
    severity: high
    status: active
    count:
      at_least: 20
      within: 1m
      group_by: [authentication.network.source.ip, origin.agent_id]
    match:
      field: authentication.outcome
      equals: failure
`

func read(t *testing.T, document string) ([]rulefile.Written, error) {
	t.Helper()
	return rulefile.Parse("counting.yml", []byte(document))
}

func counting(t *testing.T, document string) detection.Rule {
	t.Helper()

	written, err := read(t, document)
	if err != nil {
		t.Fatalf("a rule file that should be read was refused: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("the file holds %d rules", len(written))
	}
	return written[0].Program.Rule()
}

func TestARuleFileWritesACount(t *testing.T) {
	rule := counting(t, counted)

	if !rule.Count.Counts() {
		t.Fatal("a rule written with a count does not count")
	}
	if rule.Count.AtLeast != 20 || rule.Count.Within != time.Minute {
		t.Errorf("the rule counts %d inside %s", rule.Count.AtLeast, rule.Count.Within)
	}
	expected := []detection.Field{"authentication.network.source.ip", "origin.agent_id"}
	if len(rule.Count.GroupBy) != len(expected) {
		t.Fatalf("the rule groups by %v", rule.Count.GroupBy)
	}
	for index, field := range expected {
		if rule.Count.GroupBy[index] != field {
			t.Errorf("the rule groups by %s where it should group by %s", rule.Count.GroupBy[index], field)
		}
	}
}

func TestARuleFileWithoutACountCountsNothing(t *testing.T) {
	if rule := counting(t, strings.Replace(counted, `    count:
      at_least: 20
      within: 1m
      group_by: [authentication.network.source.ip, origin.agent_id]
`, "", 1)); rule.Count.Counts() {
		t.Error("a rule written without a count counts")
	}
}

// A count is refused where it was written, with the line and column, which is
// the whole reason the file reader keeps its own faults: an author is told what
// to change rather than which rule stopped working.
func TestACountIsRefusedWhereItWasWritten(t *testing.T) {
	cases := map[string]struct {
		block string
		part  string
	}{
		"a window nobody can parse":             {"      at_least: 20\n      within: soon\n", "count.within"},
		"a window a rule may not remember for":  {"      at_least: 20\n      within: 48h\n", "count.within"},
		"a threshold above what a window holds": {"      at_least: 99999\n      within: 1m\n", "count.at_least"},
		"a threshold that is not a number":      {"      at_least: many\n      within: 1m\n", "count.at_least"},
		"a count with no threshold":             {"      within: 1m\n", "count.at_least"},
		"a field the contract does not declare": {"      at_least: 20\n      within: 1m\n      group_by: [authentication.user.shoe_size]\n", "count.group_by[0]"},
		"a group that is not a list":            {"      at_least: 20\n      within: 1m\n      group_by: origin.agent_id\n", "count.group_by"},
		"a key a count is not written with":     {"      at_least: 20\n      within: 1m\n      cooldown: 5m\n", "count.cooldown"},
		"a count that is not a mapping":         {"      - at_least: 20\n", "count"},
	}

	original := "      at_least: 20\n      within: 1m\n      group_by: [authentication.network.source.ip, origin.agent_id]\n"
	for name, subject := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := read(t, strings.Replace(counted, original, subject.block, 1))
			if err == nil {
				t.Fatal("a count that should have been refused was read")
			}

			var fault *rulefile.Fault
			if !errors.As(err, &fault) {
				t.Fatalf("a rule file was refused by something other than a fault: %v", err)
			}
			if fault.Part != subject.part {
				t.Errorf("the fault names %q and should name %q: %v", fault.Part, subject.part, fault)
			}
			if fault.Line == 0 {
				t.Errorf("the fault does not say where it was written: %v", fault)
			}
		})
	}
}
