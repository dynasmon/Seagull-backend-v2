package detection_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// The event the rule in this file was written to find: a failed SSH password
// from an address that is not in the one private range the rule names.
func outside() map[detection.Field]detection.Value {
	return map[detection.Field]detection.Value{
		"authentication.outcome":           detection.TextValue("failure"),
		"authentication.service.protocol":  detection.TextValue("ssh"),
		"authentication.network.source.ip": detection.TextValue("203.0.113.10"),
	}
}

func program(t *testing.T, subject detection.Rule) *detection.Program {
	t.Helper()

	compiled, err := detection.Compile(subject)
	if err != nil {
		t.Fatalf("compile %q: %v", subject.ID, err)
	}
	return compiled
}

func TestACaseTheRuleAnswersTheWayItWasWrittenHolds(t *testing.T) {
	inside := outside()
	inside["authentication.network.source.ip"] = detection.TextValue("10.0.0.5")

	held := []detection.Case{
		{Name: "a failure from outside", Expect: detection.Matches, Event: outside()},
		{Name: "a failure from inside", Expect: detection.DoesNotMatch, Event: inside},
	}
	for _, subject := range held {
		if failure := program(t, rule()).Check(subject); failure != nil {
			t.Errorf("a case that should hold did not: %v", failure)
		}
	}
}

// A failure names the rule and the case, because a run over a tree of files has
// to say which one to look at.
func TestACaseTheRuleAnswersDifferentlyNamesItself(t *testing.T) {
	quiet := outside()
	quiet["authentication.outcome"] = detection.TextValue("success")

	failure := program(t, rule()).Check(detection.Case{
		Name:   "a failure from outside",
		Expect: detection.Matches,
		Event:  quiet,
	})
	if failure == nil {
		t.Fatal("a case the rule does not answer that way held")
	}
	if failure.Rule != "ssh.failed_password_from_outside" || failure.Case != "a failure from outside" {
		t.Errorf("the failure names rule %q case %q", failure.Rule, failure.Case)
	}
	if !strings.Contains(failure.Reason, "did not match") {
		t.Errorf("the failure reads %q", failure.Reason)
	}
}

// A case that expected quiet and got a match is told what the rule read, which
// is what turns a surprise into a rule somebody can narrow.
func TestACaseThatExpectedQuietIsToldWhatMatched(t *testing.T) {
	failure := program(t, rule()).Check(detection.Case{
		Name:   "a failure from outside",
		Expect: detection.DoesNotMatch,
		Event:  outside(),
	})
	if failure == nil {
		t.Fatal("a case that expected quiet and got a match held")
	}
	for _, field := range []string{"authentication.outcome", "authentication.network.source.ip"} {
		if !strings.Contains(failure.Reason, field) {
			t.Errorf("the failure does not say the rule read %s: %s", field, failure.Reason)
		}
	}
}

func TestACaseHoldsTheRuleToWhatItSaysAMatchIs(t *testing.T) {
	cases := map[string]struct {
		says    string
		subject detection.Case
	}{
		"a severity the rule is not": {"expects critical", detection.Case{
			Name:     "a failure from outside",
			Expect:   detection.Matches,
			Event:    outside(),
			Severity: detection.Critical,
		}},
		"evidence the match is not": {"evidenced by", detection.Case{
			Name:     "a failure from outside",
			Expect:   detection.Matches,
			Event:    outside(),
			Evidence: []detection.Field{"authentication.user.name"},
		}},
	}

	for name, expected := range cases {
		t.Run(name, func(t *testing.T) {
			failure := program(t, rule()).Check(expected.subject)
			if failure == nil {
				t.Fatalf("a case expecting %s held", name)
			}
			if !strings.Contains(failure.Reason, expected.says) {
				t.Errorf("the failure reads %q and should say %q", failure.Reason, expected.says)
			}
		})
	}
}

// Evidence is the set of fields the rule read, so the order a case writes them
// in is not part of what it asserts.
func TestEvidenceIsWhatTheRuleReadWhateverOrderTheCaseWritesIt(t *testing.T) {
	read := []detection.Field{
		"authentication.network.source.ip",
		"authentication.outcome",
		"authentication.service.protocol",
	}
	backwards := []detection.Field{read[2], read[1], read[0]}

	for _, evidence := range [][]detection.Field{read, backwards} {
		failure := program(t, rule()).Check(detection.Case{
			Name:     "a failure from outside",
			Expect:   detection.Matches,
			Event:    outside(),
			Evidence: evidence,
			Severity: detection.Medium,
		})
		if failure != nil {
			t.Errorf("the evidence written %v did not hold: %v", evidence, failure)
		}
	}
}

// A field the case does not name is a field the event does not carry, so a rule
// asking about it decides on an event that is short of it rather than on one
// carrying a zero the case never wrote.
func TestAFieldACaseDoesNotNameIsOneTheEventDoesNotCarry(t *testing.T) {
	subject := rule()
	subject.Match = detection.Predicate{Field: "authentication.user.name", Operator: detection.Present}

	failure := program(t, subject).Check(detection.Case{
		Name:   "an event carrying no user",
		Expect: detection.DoesNotMatch,
		Event:  outside(),
	})
	if failure != nil {
		t.Errorf("a field nobody wrote was carried by the event: %v", failure)
	}
}

func TestACaseTheRuleCannotBeAskedIsRefused(t *testing.T) {
	cases := map[string]struct {
		part    string
		says    string
		subject detection.Case
	}{
		"a case with no name": {"tests[0].name", "is missing", detection.Case{
			Expect: detection.Matches, Event: outside(),
		}},
		"an answer deciding does not have": {"tests[0].expect", "match or no_match", detection.Case{
			Name: "a case", Expect: "fires", Event: outside(),
		}},
		"a case carrying no event": {"tests[0].event", "carries nothing", detection.Case{
			Name: "a case", Expect: detection.Matches,
		}},
		"a field the contract does not declare": {"tests[0].event.authentication.user.nam", "not a field the contract declares", detection.Case{
			Name:   "a case",
			Expect: detection.Matches,
			Event:  map[detection.Field]detection.Value{"authentication.user.nam": detection.TextValue("root")},
		}},
		"the class of the event": {"tests[0].event.event_class", "takes from the rule", detection.Case{
			Name:   "a case",
			Expect: detection.Matches,
			Event:  map[detection.Field]detection.Value{"event_class": detection.TextValue("authentication")},
		}},
		"a value the field cannot hold": {"tests[0].event.authentication.network.source.port", "holds number and is given", detection.Case{
			Name:   "a case",
			Expect: detection.Matches,
			Event:  map[detection.Field]detection.Value{"authentication.network.source.port": detection.TextValue("22")},
		}},
		"a choice the contract does not declare": {"tests[0].event.authentication.outcome", "the contract declares", detection.Case{
			Name:   "a case",
			Expect: detection.Matches,
			Event:  map[detection.Field]detection.Value{"authentication.outcome": detection.TextValue("refused")},
		}},
		"a number the field cannot hold": {"tests[0].event.authentication.network.source.port", "cannot hold", detection.Case{
			Name:   "a case",
			Expect: detection.Matches,
			Event:  map[detection.Field]detection.Value{"authentication.network.source.port": detection.NumberValue(-1)},
		}},
		"text nothing can be told from absence": {"tests[0].event.authentication.user.name", "told from carrying nothing", detection.Case{
			Name:   "a case",
			Expect: detection.Matches,
			Event:  map[detection.Field]detection.Value{"authentication.user.name": detection.TextValue("")},
		}},
		"a number nothing can be told from absence": {"tests[0].event.authentication.network.source.port", "told from carrying nothing", detection.Case{
			Name:   "a case",
			Expect: detection.Matches,
			Event:  map[detection.Field]detection.Value{"authentication.network.source.port": detection.NumberValue(0)},
		}},
		"a severity expected of quiet": {"tests[0].severity", "only a match carries one", detection.Case{
			Name: "a case", Expect: detection.DoesNotMatch, Event: outside(), Severity: detection.Medium,
		}},
		"evidence expected of quiet": {"tests[0].evidence", "only a match carries any", detection.Case{
			Name:     "a case",
			Expect:   detection.DoesNotMatch,
			Event:    outside(),
			Evidence: []detection.Field{"authentication.outcome"},
		}},
		"a severity that is not one": {"tests[0].severity", "not one of low", detection.Case{
			Name: "a case", Expect: detection.Matches, Event: outside(), Severity: "urgent",
		}},
		"evidence the contract does not declare": {"tests[0].evidence[0]", "not a field the contract declares", detection.Case{
			Name:     "a case",
			Expect:   detection.Matches,
			Event:    outside(),
			Evidence: []detection.Field{"authentication.user.nam"},
		}},
	}

	for name, refused := range cases {
		t.Run(name, func(t *testing.T) {
			err := rule().Accepts("tests[0]", refused.subject)
			if err == nil {
				t.Fatalf("a case with %s was accepted", name)
			}

			var violation *detection.Violation
			if !errors.As(err, &violation) {
				t.Fatalf("the refusal is a %T and should name the part that is wrong", err)
			}
			if violation.Part != refused.part {
				t.Errorf("the refusal points at %q and should point at %q: %v", violation.Part, refused.part, err)
			}
			if !strings.Contains(violation.Reason, refused.says) {
				t.Errorf("the refusal reads %q and should say %q", violation.Reason, refused.says)
			}
		})
	}
}

// A case the rule accepts is one it can be asked, so what the harness runs is
// only ever a case that describes an event the contract can hold.
func TestACaseTheRuleAcceptsIsOneItCanBeAsked(t *testing.T) {
	subject := detection.Case{
		Name:        "a failure from outside",
		Description: "The event the rule was written to find.",
		Expect:      detection.Matches,
		Event:       outside(),
		Evidence:    []detection.Field{"authentication.outcome"},
		Severity:    detection.Medium,
	}
	if err := rule().Accepts("tests[0]", subject); err != nil {
		t.Fatalf("a case the rule can be asked was refused: %v", err)
	}
}

// Checking reads nothing and keeps nothing, so the same case asked twice answers
// the same way and neither answer is built from the last one.
func TestCheckingACaseTwiceAnswersTheSameWay(t *testing.T) {
	compiled := program(t, rule())
	subject := detection.Case{Name: "a failure from outside", Expect: detection.Matches, Event: outside()}

	for range 2 {
		if failure := compiled.Check(subject); failure != nil {
			t.Errorf("a case that should hold did not: %v", failure)
		}
	}
}
