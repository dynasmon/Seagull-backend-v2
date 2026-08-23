package detection_test

import (
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

func TestARuleThatCouldNeverMatchIsRefused(t *testing.T) {
	cases := map[string]struct {
		part  string
		says  string
		match detection.Expression
	}{
		"two values for one field": {"match.all", "which nothing satisfies", detection.All{Terms: []detection.Expression{
			text("authentication.user.name", detection.Equals, "root"),
			text("authentication.user.name", detection.Equals, "admin"),
		}}},
		"two lists that do not overlap": {"match.all", "which nothing satisfies", detection.All{Terms: []detection.Expression{
			text("authentication.user.name", detection.OneOf, "root", "admin"),
			text("authentication.user.name", detection.OneOf, "nobody"),
		}}},
		"a range with nothing in it": {"match.all", "which nothing satisfies", detection.All{Terms: []detection.Expression{
			count("authentication.network.source.port", detection.AtLeast, 1024),
			count("authentication.network.source.port", detection.AtMost, 22),
		}}},
		"a range that excludes its own edge": {"match.all", "which nothing satisfies", detection.All{Terms: []detection.Expression{
			count("authentication.network.source.port", detection.Above, 22),
			count("authentication.network.source.port", detection.Below, 22),
		}}},
		"a value outside the range asked for": {"match.all", "which nothing satisfies", detection.All{Terms: []detection.Expression{
			count("authentication.network.source.port", detection.Equals, 22),
			count("authentication.network.source.port", detection.AtLeast, 1024),
		}}},
		"a value that cannot begin the way it is asked to": {"match.all", "which nothing satisfies", detection.All{Terms: []detection.Expression{
			text("authentication.user.name", detection.Equals, "root"),
			text("authentication.user.name", detection.StartsWith, "adm"),
		}}},
		"a value the rule also excludes": {"match.all", "which nothing satisfies", detection.All{Terms: []detection.Expression{
			text("authentication.user.name", detection.OneOf, "root"),
			detection.Not{Term: text("authentication.user.name", detection.OneOf, "root", "admin")},
		}}},
		"a field asked to be there and not to be": {"match.all", "can never match", detection.All{Terms: []detection.Expression{
			text("authentication.network.source.ip", detection.Present),
			detection.Not{Term: text("authentication.network.source.ip", detection.Present)},
		}}},
		"a question and its own negation": {"match.all", "can never match", detection.All{Terms: []detection.Expression{
			text("authentication.user.name", detection.Equals, "root"),
			detection.Not{Term: text("authentication.user.name", detection.Equals, "root")},
		}}},
		"two beginnings neither of which is the other": {"match.all", "which nothing satisfies", detection.All{Terms: []detection.Expression{
			text("collection.source", detection.StartsWith, "/usr"),
			text("collection.source", detection.StartsWith, "/etc"),
		}}},
		"two endings neither of which is the other": {"match.all", "which nothing satisfies", detection.All{Terms: []detection.Expression{
			text("origin.host.hostname", detection.EndsWith, ".dmz.internal"),
			text("origin.host.hostname", detection.EndsWith, ".corp.internal"),
		}}},
		"a contradiction one level down": {"match.all", "which nothing satisfies", detection.All{Terms: []detection.Expression{
			detection.All{Terms: []detection.Expression{text("authentication.user.name", detection.Equals, "root")}},
			text("authentication.user.name", detection.Equals, "admin"),
		}}},
	}

	for name, broken := range cases {
		t.Run(name, func(t *testing.T) {
			violation := compileRefusal(t, asking(broken.match))
			if violation.Part != broken.part {
				t.Errorf("the refusal points at %q and should point at %q", violation.Part, broken.part)
			}
			if !strings.Contains(violation.Reason, broken.says) {
				t.Errorf("the refusal reads %q and should say %q", violation.Reason, broken.says)
			}
		})
	}
}

// The other half of the same mistake: a rule that fires on every event says as
// little as one that never fires.
func TestARuleThatMatchesEveryEventIsRefused(t *testing.T) {
	violation := compileRefusal(t, asking(detection.Any{Terms: []detection.Expression{
		text("authentication.user.name", detection.Equals, "root"),
		detection.Not{Term: text("authentication.user.name", detection.Equals, "root")},
	}}))

	if violation.Part != "match.any" {
		t.Errorf("the refusal points at %q", violation.Part)
	}
	if !strings.Contains(violation.Reason, "matches every event") {
		t.Errorf("the refusal reads %q", violation.Reason)
	}
}

func TestARuleThatCanMatchIsCompiled(t *testing.T) {
	cases := map[string]detection.Expression{
		"a value that answers both questions": detection.All{Terms: []detection.Expression{
			text("authentication.user.name", detection.Equals, "root"),
			text("authentication.user.name", detection.Contains, "oo"),
		}},
		"a range with room in it": detection.All{Terms: []detection.Expression{
			count("authentication.network.source.port", detection.AtLeast, 1024),
			count("authentication.network.source.port", detection.AtMost, 65535),
		}},
		"one beginning inside the other": detection.All{Terms: []detection.Expression{
			text("collection.source", detection.StartsWith, "/var/log"),
			text("collection.source", detection.StartsWith, "/var"),
		}},
		"two fields that disagree about nothing": detection.All{Terms: []detection.Expression{
			text("authentication.user.name", detection.Equals, "root"),
			text("authentication.user.domain", detection.Equals, "corp"),
		}},
		"a choice between two values": detection.Any{Terms: []detection.Expression{
			text("authentication.user.name", detection.Equals, "root"),
			text("authentication.user.name", detection.Equals, "admin"),
		}},
	}

	for name, match := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := detection.Compile(asking(match)); err != nil {
				t.Errorf("a rule that can match was refused: %v", err)
			}
		})
	}
}

// What the check deliberately does not decide, kept as a test so that the limit
// is visible rather than discovered. Both of these can be shown to match
// nothing, and neither is refused: a conjunction is only narrowed by what it
// asks directly, and no combination of questions is searched for emptiness.
func TestWhatTheCheckLeavesAlone(t *testing.T) {
	cases := map[string]detection.Expression{
		"a negation of what a disjunction asks": detection.All{Terms: []detection.Expression{
			detection.Any{Terms: []detection.Expression{text("authentication.user.name", detection.Equals, "root")}},
			detection.Not{Term: text("authentication.user.name", detection.Equals, "root")},
		}},
		"two exclusions that together leave nothing": detection.All{Terms: []detection.Expression{
			text("authentication.user.name", detection.OneOf, "root", "admin"),
			detection.Not{Term: text("authentication.user.name", detection.Equals, "root")},
			detection.Not{Term: text("authentication.user.name", detection.Equals, "admin")},
		}},
	}

	for name, match := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := detection.Compile(asking(match)); err != nil {
				t.Errorf("the check decided something it does not claim to decide: %v", err)
			}
		})
	}
}

func asking(match detection.Expression) detection.Rule {
	subject := rule()
	subject.Match = match
	return subject
}

func text(field detection.Field, operator detection.Operator, values ...string) detection.Predicate {
	written := make([]detection.Value, 0, len(values))
	for _, value := range values {
		written = append(written, detection.TextValue(value))
	}
	return detection.Predicate{Field: field, Operator: operator, Values: written}
}

func count(field detection.Field, operator detection.Operator, value float64) detection.Predicate {
	return detection.Predicate{Field: field, Operator: operator, Values: []detection.Value{detection.NumberValue(value)}}
}
