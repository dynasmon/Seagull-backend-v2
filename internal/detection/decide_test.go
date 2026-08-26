package detection_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The event the rest of this file changes one field at a time: what the ssh
// collector actually produces, so a rule is decided against the shape the
// pipeline carries rather than against one written to suit it.
func event(shape func(*eventv1.Authentication)) *eventv1.Event {
	record := fixtures.SSHAuthentication{}.Event()
	if shape != nil {
		shape(record.GetAuthentication())
	}
	return record
}

func running(t *testing.T, match detection.Expression) *detection.Program {
	t.Helper()

	program, err := detection.Compile(asking(match))
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}
	return program
}

func TestARuleDecidesTheEventItWasWrittenFor(t *testing.T) {
	program, err := detection.Compile(rule())
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	match, held := program.Decide(event(nil))
	if !held {
		t.Fatal("a failed ssh password from outside the estate did not match the rule written for it")
	}
	if match.Rule.ID != rule().ID {
		t.Errorf("the match names rule %q", match.Rule.ID)
	}

	asked := []string{
		`authentication.outcome equals, and the event holds failure`,
		`authentication.service.protocol equals, and the event holds "ssh"`,
		`authentication.network.source.ip not starts_with, and the event holds "203.0.113.10"`,
	}
	if written := lines(match.Evidence); !equal(written, asked) {
		t.Errorf("the match is evidenced by\n%s\nand should be evidenced by\n%s",
			strings.Join(written, "\n"), strings.Join(asked, "\n"))
	}
}

func TestAnEventThatAnswersTheRuleDifferentlyDoesNotMatch(t *testing.T) {
	program, err := detection.Compile(rule())
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	succeeded := event(func(body *eventv1.Authentication) {
		body.Outcome = eventv1.Outcome_OUTCOME_SUCCESS
	})
	if match, held := program.Decide(succeeded); held {
		t.Errorf("a successful authentication matched a rule about failures: %v", lines(match.Evidence))
	}
}

// Every operator the language has, against a value the event carries and a
// value it does not. The pairs are what an operator means, and the ones sitting
// on the boundary are here on purpose: `above` and `below` exclude the number
// they name and `at_least` and `at_most` include it.
func TestEveryOperatorAnswersTheEventInFrontOfIt(t *testing.T) {
	type question struct {
		asked detection.Predicate
		holds bool
	}

	answered := map[detection.Operator][]question{
		detection.Equals: {
			{text("authentication.outcome", detection.Equals, "failure"), true},
			{text("authentication.outcome", detection.Equals, "success"), false},
			{text("authentication.user.name", detection.Equals, "root"), true},
			{text("authentication.user.name", detection.Equals, "Root"), false},
		},
		detection.OneOf: {
			{text("authentication.user.name", detection.OneOf, "admin", "root"), true},
			{text("authentication.user.name", detection.OneOf, "admin", "backup"), false},
			{count("authentication.network.source.port", detection.OneOf, 54321), true},
		},
		detection.Contains: {
			{text("authentication.raw_record", detection.Contains, "Failed password"), true},
			{text("authentication.raw_record", detection.Contains, "Accepted"), false},
		},
		detection.StartsWith: {
			{text("authentication.network.source.ip", detection.StartsWith, "203.0.113."), true},
			{text("authentication.network.source.ip", detection.StartsWith, "10."), false},
		},
		detection.EndsWith: {
			{text("authentication.service.name", detection.EndsWith, "shd"), true},
			{text("authentication.service.name", detection.EndsWith, "shd "), false},
		},
		detection.Above: {
			{count("authentication.network.source.port", detection.Above, 54320), true},
			{count("authentication.network.source.port", detection.Above, 54321), false},
		},
		detection.AtLeast: {
			{count("authentication.network.source.port", detection.AtLeast, 54321), true},
			{count("authentication.network.source.port", detection.AtLeast, 54322), false},
		},
		detection.Below: {
			{count("authentication.network.source.port", detection.Below, 54322), true},
			{count("authentication.network.source.port", detection.Below, 54321), false},
		},
		detection.AtMost: {
			{count("authentication.network.source.port", detection.AtMost, 54321), true},
			{count("authentication.network.source.port", detection.AtMost, 54320), false},
		},
		detection.Present: {
			{text("authentication.user.name", detection.Present), true},
			{text("authentication.user.domain", detection.Present), false},
		},
	}

	for _, operator := range detection.Operators() {
		cases, covered := answered[operator]
		if !covered {
			t.Errorf("%s is an operator nothing here decides an event with", operator)
			continue
		}
		for _, decided := range cases {
			program := running(t, decided.asked)
			if _, held := program.Decide(event(nil)); held != decided.holds {
				t.Errorf("%s answered %t and should have answered %t", program, held, decided.holds)
			}
		}
	}
}

// The contract does not distinguish a field an event does not carry from one
// carrying the zero value, so neither does a rule: everything asked of an absent
// field is false, and `present` is the one way to ask about it.
func TestAFieldTheEventDoesNotCarryAnswersNoQuestion(t *testing.T) {
	blank := event(func(body *eventv1.Authentication) {
		body.User = nil
		body.Network.Source.Port = 0
		body.Outcome = eventv1.Outcome_OUTCOME_UNSPECIFIED
	})

	for _, asked := range []detection.Predicate{
		text("authentication.user.name", detection.Equals, "root"),
		text("authentication.user.name", detection.Present),
		count("authentication.network.source.port", detection.AtMost, 1024),
		count("authentication.network.source.port", detection.AtLeast, 0),
		text("authentication.outcome", detection.Equals, "unspecified"),
	} {
		program := running(t, asked)
		if _, held := program.Decide(blank); held {
			t.Errorf("%s held against an event that does not carry the field", program)
		}
	}
}

// Which is what makes a negation say the useful thing: a rule asking that a
// field is not something also holds when the event never said.
func TestARuleThatAsksAFieldIsNotSomethingHoldsWhenItIsNotThere(t *testing.T) {
	blank := event(func(body *eventv1.Authentication) { body.User = nil })

	program := running(t, detection.Not{
		Term: text("authentication.user.name", detection.Equals, "backup"),
	})
	match, held := program.Decide(blank)
	if !held {
		t.Fatal("an event carrying no user did not answer a rule about the user not being backup")
	}

	asked := []string{"authentication.user.name not equals, and the event does not carry it"}
	if written := lines(match.Evidence); !equal(written, asked) {
		t.Errorf("the match is evidenced by %v", written)
	}
}

// A rule reads the class it was written for. Nothing else reaches it on the
// route, and a harness handing it another event gets the same answer.
func TestARuleOnlyDecidesItsOwnClass(t *testing.T) {
	program, err := detection.Compile(rule())
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	other := event(nil)
	other.EventClass = eventv1.EventClass_EVENT_CLASS_UNSPECIFIED
	if _, held := program.Decide(other); held {
		t.Error("a rule written for authentication decided an event of another class")
	}
	if _, held := program.Decide(nil); held {
		t.Error("a rule decided nothing at all")
	}
}

// The branch that held is the reason; the ones tried before it are not.
func TestADisjunctionIsEvidencedByTheBranchThatHeld(t *testing.T) {
	program := running(t, detection.Any{Terms: []detection.Expression{
		text("authentication.user.name", detection.Equals, "backup"),
		text("authentication.service.protocol", detection.Equals, "ssh"),
		text("authentication.method", detection.Equals, "password"),
	}})

	match, held := program.Decide(event(nil))
	if !held {
		t.Fatal("an event answering one branch did not answer the disjunction")
	}

	asked := []string{`authentication.service.protocol equals, and the event holds "ssh"`}
	if written := lines(match.Evidence); !equal(written, asked) {
		t.Errorf("the match is evidenced by %v", written)
	}
}

// A disjunction that held nowhere is evidenced by every branch, because under a
// negation all of them failing is exactly why the rule matched.
func TestANegatedDisjunctionIsEvidencedByEveryBranch(t *testing.T) {
	program := running(t, detection.Not{Term: detection.Any{Terms: []detection.Expression{
		text("authentication.user.name", detection.Equals, "backup"),
		text("authentication.method", detection.Equals, "publickey"),
	}}})

	match, held := program.Decide(event(nil))
	if !held {
		t.Fatal("an event answering neither branch did not answer the negation")
	}

	asked := []string{
		`authentication.user.name not equals, and the event holds "root"`,
		`authentication.method not equals, and the event holds "password"`,
	}
	if written := lines(match.Evidence); !equal(written, asked) {
		t.Errorf("the match is evidenced by %v", written)
	}
}

// Nothing the compiler refuses can reach the executor, so an operator never
// meets a value of a type it has no answer for.
func TestAComparisonTheFieldCannotAnswerIsRefusedBeforeItRuns(t *testing.T) {
	for _, asked := range []detection.Predicate{
		text("authentication.network.source.port", detection.Contains, "54"),
		text("authentication.user.name", detection.Contains, ""),
		count("authentication.user.name", detection.Above, 1),
		text("authentication.outcome", detection.Equals, "refused"),
		count("authentication.network.source.port", detection.AtLeast, -1),
	} {
		if _, err := detection.Compile(asking(asked)); err == nil {
			t.Errorf("%s %s compiled, and nothing would ever have answered it", asked.Field, asked.Operator)
		}
	}
}

// Deciding reads the event and changes nothing, in it or in the program, so the
// same question asked twice is answered the same way and a replay of the same
// telemetry produces the same detections.
func TestDecidingAnEventLeavesItAsItArrived(t *testing.T) {
	program, err := detection.Compile(rule())
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	record := event(nil)
	before := proto.Clone(record)

	first, held := program.Decide(record)
	if !held {
		t.Fatal("the event did not match the rule written for it")
	}
	if !proto.Equal(before, record) {
		t.Error("deciding an event changed it")
	}

	second, again := program.Decide(record)
	if !again || !equal(lines(first.Evidence), lines(second.Evidence)) {
		t.Errorf("the same event decided twice gave %v and then %v", lines(first.Evidence), lines(second.Evidence))
	}
}

// Most events answer most rules with no, and that answer is the whole cost of
// detection on a busy backbone: it walks the tree and allocates nothing.
func TestAnEventThatMatchesNothingCostsNoMemory(t *testing.T) {
	program, err := detection.Compile(rule())
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	succeeded := event(func(body *eventv1.Authentication) {
		body.Outcome = eventv1.Outcome_OUTCOME_SUCCESS
	})
	if allocations := testing.AllocsPerRun(100, func() { program.Decide(succeeded) }); allocations != 0 {
		t.Errorf("deciding an event against a rule it does not match allocated %.0f times", allocations)
	}
}

func BenchmarkDecideAnEventThatMatches(b *testing.B) {
	program, err := detection.Compile(rule())
	if err != nil {
		b.Fatalf("a rule that should run was refused: %v", err)
	}

	record := fixtures.SSHAuthentication{}.Event()
	b.ReportAllocs()
	for b.Loop() {
		if _, held := program.Decide(record); !held {
			b.Fatal("the event did not match the rule written for it")
		}
	}
}

func BenchmarkDecideAnEventThatDoesNot(b *testing.B) {
	program, err := detection.Compile(rule())
	if err != nil {
		b.Fatalf("a rule that should run was refused: %v", err)
	}

	record := fixtures.SSHAuthentication{Outcome: eventv1.Outcome_OUTCOME_SUCCESS}.Event()
	b.ReportAllocs()
	for b.Loop() {
		if _, held := program.Decide(record); held {
			b.Fatal("a successful authentication matched a rule about failures")
		}
	}
}

func lines(evidence []detection.Evidence) []string {
	written := make([]string, 0, len(evidence))
	for _, seen := range evidence {
		written = append(written, seen.String())
	}
	return written
}

func equal(one, other []string) bool {
	if len(one) != len(other) {
		return false
	}
	for index := range one {
		if one[index] != other[index] {
			return false
		}
	}
	return true
}

// A rule refusing three private prefixes asks three questions of one field and
// the event gives one answer. What was asked in full is not kept, so three
// copies of that answer would say nothing three times — and the rule the local
// stack ships is written exactly this way, so this is what reaches a detection.
func TestOneAnswerIsWrittenDownOnceHoweverOftenItWasAsked(t *testing.T) {
	program := running(t, detection.Not{Term: detection.Any{Terms: []detection.Expression{
		text("authentication.network.source.ip", detection.StartsWith, "10."),
		text("authentication.network.source.ip", detection.StartsWith, "192.168."),
		text("authentication.network.source.ip", detection.StartsWith, "127."),
	}}})

	match, held := program.Decide(event(nil))
	if !held {
		t.Fatal("an address outside every private range did not match a rule refusing them")
	}

	written := lines(match.Evidence)
	if len(written) != 1 {
		t.Errorf("one field answered one way and the match carries %d observations: %v", len(written), written)
	}
}

// Two questions of one field that the event answers differently stay two
// observations: what is dropped is a repetition, never a distinction.
func TestTwoDifferentAnswersAboutOneFieldAreBothKept(t *testing.T) {
	program := running(t, detection.All{Terms: []detection.Expression{
		text("authentication.network.source.ip", detection.StartsWith, "203."),
		detection.Not{Term: text("authentication.network.source.ip", detection.StartsWith, "10.")},
	}})

	match, held := program.Decide(event(nil))
	if !held {
		t.Fatal("an external address did not match a rule written for one")
	}
	if written := lines(match.Evidence); len(written) != 2 {
		t.Errorf("one field was asked two different ways and the match carries %d observations: %v",
			len(written), written)
	}
}
