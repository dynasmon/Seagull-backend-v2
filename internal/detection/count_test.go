package detection_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func counting(shape func(*detection.Count)) detection.Rule {
	subject := rule()
	subject.Count = detection.Count{
		AtLeast: 20,
		Within:  time.Minute,
		GroupBy: []detection.Field{"authentication.network.source.ip", "origin.agent_id"},
	}
	if shape != nil {
		shape(&subject.Count)
	}
	return subject
}

func refusal(t *testing.T, subject detection.Rule) *detection.Violation {
	t.Helper()

	_, err := detection.Compile(subject)
	if err == nil {
		t.Fatal("a rule that should have been refused compiled")
	}
	var violation *detection.Violation
	if !errors.As(err, &violation) {
		t.Fatalf("a rule was refused by something other than a violation: %v", err)
	}
	return violation
}

func TestARuleWithoutACountDecidesOneEventAtATime(t *testing.T) {
	program, err := detection.Compile(rule())
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}
	if program.Counts() {
		t.Error("a rule that was written without a count counts")
	}
	if group := program.Group(fixtures.SSHAuthentication{}.Event()); group != nil {
		t.Errorf("a rule that counts nothing bound %v", group)
	}
}

// A threshold above what one key may hold could never be reached, so the rule
// is refused where it is written rather than left never firing. This is the
// ceiling the state boundary declares, met by the compiler that ADR 18 said
// would have to meet it.
func TestACountAboveWhatAWindowMayHoldIsRefused(t *testing.T) {
	violation := refusal(t, counting(func(c *detection.Count) { c.AtLeast = detection.MaxCount + 1 }))

	if violation.Part != "count.at_least" {
		t.Errorf("the refusal names %q", violation.Part)
	}
	if program, err := detection.Compile(counting(func(c *detection.Count) { c.AtLeast = detection.MaxCount })); err != nil {
		t.Errorf("a rule counting to exactly the ceiling was refused: %v", err)
		_ = program
	}
}

func TestACountIsRefusedForWhatItCannotAnswer(t *testing.T) {
	cases := map[string]struct {
		shape func(*detection.Count)
		part  string
	}{
		"counting to one":    {func(c *detection.Count) { c.AtLeast = 1 }, "count.at_least"},
		"no window":          {func(c *detection.Count) { c.Within = 0 }, "count.within"},
		"a window of a week": {func(c *detection.Count) { c.Within = 7 * 24 * time.Hour }, "count.within"},
		"a threshold and only a window": {func(c *detection.Count) {
			c.AtLeast, c.GroupBy = 0, nil
		}, "count.at_least"},
		"too many group fields": {func(c *detection.Count) {
			c.GroupBy = nil
			for range detection.MaxGroupBy + 1 {
				c.GroupBy = append(c.GroupBy, "authentication.user.name")
			}
		}, "count.group_by"},
	}

	for name, subject := range cases {
		t.Run(name, func(t *testing.T) {
			if violation := refusal(t, counting(subject.shape)); violation.Part != subject.part {
				t.Errorf("the refusal names %q and should name %q", violation.Part, subject.part)
			}
		})
	}
}

// Three fields no count can group by, each for a reason of its own: the class
// every event the rule reads already shares, the tenant a count is always
// inside, and an identifier no two events could ever share.
func TestACountIsRefusedForGroupingByWhatCannotGroup(t *testing.T) {
	cases := map[string]detection.Field{
		"the class":                             "event_class",
		"the tenant":                            "origin.tenant_id",
		"the event identifier":                  "event_id",
		"a field the contract does not declare": "authentication.user.shoe_size",
		"a message rather than a scalar":        "authentication.user",
	}

	for name, field := range cases {
		t.Run(name, func(t *testing.T) {
			violation := refusal(t, counting(func(c *detection.Count) { c.GroupBy = []detection.Field{field} }))
			if violation.Part != "count.group_by[0]" {
				t.Errorf("the refusal names %q", violation.Part)
			}
		})
	}
}

func TestACountIsRefusedForGroupingByTheSameFieldTwice(t *testing.T) {
	violation := refusal(t, counting(func(c *detection.Count) {
		c.GroupBy = []detection.Field{"authentication.user.name", "authentication.user.name"}
	}))
	if violation.Part != "count.group_by[1]" {
		t.Errorf("the refusal names %q", violation.Part)
	}
}

// A count with no grouping is a count of everything the tenant produced that
// matched, which is blunt and legitimate: the tenant is always part of the key,
// so an ungrouped count is the cheapest state there is rather than the widest.
func TestACountMayGroupByNothing(t *testing.T) {
	program, err := detection.Compile(counting(func(c *detection.Count) { c.GroupBy = nil }))
	if err != nil {
		t.Fatalf("an ungrouped count was refused: %v", err)
	}
	if group := program.Group(fixtures.SSHAuthentication{}.Event()); len(group) != 0 {
		t.Errorf("an ungrouped count bound %v", group)
	}
}

func TestAGroupBindsWhatTheEventHeld(t *testing.T) {
	program, err := detection.Compile(counting(func(c *detection.Count) {
		c.GroupBy = []detection.Field{"authentication.network.source.ip", "authentication.network.source.port", "authentication.outcome"}
	}))
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	group := program.Group(fixtures.SSHAuthentication{SourceIP: "203.0.113.10", SourcePort: 54321}.Event())
	expected := []detection.Binding{
		{Field: "authentication.network.source.ip", Value: "203.0.113.10"},
		{Field: "authentication.network.source.port", Value: "54321"},
		{Field: "authentication.outcome", Value: "failure"},
	}
	if len(group) != len(expected) {
		t.Fatalf("the event bound %d fields and the rule groups by %d", len(group), len(expected))
	}
	for index, bound := range group {
		if bound != expected[index] {
			t.Errorf("%s bound %q and should have bound %q", bound.Field, bound.Value, expected[index].Value)
		}
	}
}

// ADR 9 carried into the key: an event that names no source address is its own
// group rather than one that counts alongside every address there is.
func TestAnAbsentGroupFieldIsItsOwnGroup(t *testing.T) {
	program, err := detection.Compile(counting(func(c *detection.Count) {
		c.GroupBy = []detection.Field{"authentication.network.source.ip"}
	}))
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	record := fixtures.SSHAuthentication{}.Event()
	record.GetAuthentication().GetNetwork().Source = nil

	group := program.Group(record)
	if len(group) != 1 || !group[0].Absent || group[0].Value != "" {
		t.Fatalf("an absent address bound %#v", group)
	}
	if held := program.Group(fixtures.SSHAuthentication{SourceIP: "203.0.113.10"}.Event()); held[0] == group[0] {
		t.Error("an event carrying an address bound the same group as one carrying none")
	}
}

func TestTheSameEventBindsTheSameGroupTwice(t *testing.T) {
	program, err := detection.Compile(counting(nil))
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	record := fixtures.SSHAuthentication{}.Event()
	first, second := program.Group(record), program.Group(record)
	if len(first) != len(second) {
		t.Fatalf("the same event bound %d fields and then %d", len(first), len(second))
	}
	for index := range first {
		if first[index] != second[index] {
			t.Errorf("%s bound %q and then %q", first[index].Field, first[index].Value, second[index].Value)
		}
	}
}

func TestACountIsPartOfWhatARuleIsWrittenAs(t *testing.T) {
	if (detection.Count{}).Counts() {
		t.Error("a rule with nothing written under count counts")
	}
	if !(detection.Count{Within: time.Minute}).Counts() {
		t.Error("half a count is read as no count at all")
	}
	if class := eventv1.EventClass_EVENT_CLASS_AUTHENTICATION; counting(nil).Class != class {
		t.Errorf("the fixture is written for %v", counting(nil).Class)
	}
}
