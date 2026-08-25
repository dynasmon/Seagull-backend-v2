package detection

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The field an event says its class in, which a case takes from the rule it was
// written for rather than saying itself.
const classField Field = "event_class"

// One event a rule was written to be sure about, and what the rule should say
// about it.
//
// A case is not part of the rule. Writing one changes nothing about what any
// event decides, so it does not change the ruleset either, and a detection made
// before the case existed is still traceable to the same rules. It is kept
// beside the rule all the same, because a rule that travels without its cases is
// a rule nobody can change safely — that is the one part of v1's rule format
// worth keeping.
type Case struct {
	Name        string
	Description string
	Expect      Expectation

	// The event, in the same vocabulary the rule matches on. A field the case
	// does not name is a field the event does not carry, which is how a case
	// says that something is absent.
	Event map[Field]Value

	// What a match has to be evidenced by, and what the rule has to be, when
	// the case is written to hold those too. Neither is asked when absent.
	Evidence []Field
	Severity Severity
}

// What the rule is expected to say, which is what deciding can answer. A case
// documenting a false positive is one that expects no match and is named after
// the false positive it documents: a third answer would be the same assertion
// under a second name.
type Expectation string

const (
	Matches      Expectation = "match"
	DoesNotMatch Expectation = "no_match"
)

var expectations = map[Expectation]struct{}{Matches: {}, DoesNotMatch: {}}

// Every expectation a case can be written with, sorted, so a refusal can say
// what was available instead.
func Expectations() []Expectation {
	written := make([]Expectation, 0, len(expectations))
	for expectation := range expectations {
		written = append(written, expectation)
	}
	slices.Sort(written)
	return written
}

// A case the rule did not answer the way it was written to, naming the rule and
// the case, so that a run over a whole tree says which one to look at.
type Failure struct {
	Rule   ID
	Case   string
	Reason string
}

func (f *Failure) Error() string {
	return fmt.Sprintf("rule %q: case %q: %s", f.Rule, f.Case, f.Reason)
}

// Whether the rule can be asked this case at all: it is named, it expects one of
// the two answers there are, and every field it sets is one the contract
// declares, one a rule of this class can reach, and one that can hold what the
// case gives it.
//
// Held where the case is written, for the same reason a rule is: a fixture
// naming a field that has moved is a case that passes by describing an event
// nobody meant.
func (r Rule) Accepts(part string, subject Case) error {
	if err := r.text(part+".name", subject.Name, MaxNameLength, true); err != nil {
		return err
	}
	if err := r.text(part+".description", subject.Description, MaxDescriptionLength, false); err != nil {
		return err
	}
	if _, declared := expectations[subject.Expect]; !declared {
		return r.violation(part+".expect", fmt.Sprintf("is %q, and a case expects %s", subject.Expect, written(Expectations())))
	}
	switch {
	case len(subject.Event) == 0:
		return r.violation(part+".event", "carries nothing: a case is an event the rule is asked about")
	case len(subject.Event) > MaxCaseFields:
		return r.violation(part+".event", fmt.Sprintf("sets %d fields, above the ceiling of %d", len(subject.Event), MaxCaseFields))
	}

	for _, field := range slices.Sorted(maps.Keys(subject.Event)) {
		if err := r.carries(part+".event."+string(field), field, subject.Event[field]); err != nil {
			return err
		}
	}
	return r.awaits(part, subject)
}

func (r Rule) carries(where string, field Field, value Value) error {
	kind, declared := KindOf(field)
	if !declared {
		return r.violation(where, "is not a field the contract declares")
	}
	if field == classField {
		return r.violation(where, "is the class of the event, which a case takes from the rule it is written for")
	}
	if !AddressableBy(field, r.Class) {
		return r.violation(where, fmt.Sprintf("belongs to another class, so a %s event does not carry it", className(r.Class)))
	}
	if !value.fits(kind) {
		return r.violation(where, fmt.Sprintf("holds %s and is given %s", kind, value))
	}
	if kind == Choice && !names(value.Text(), ChoicesOf(field)) {
		return r.violation(where, fmt.Sprintf("is given %s, and the contract declares %s", value, strings.Join(ChoicesOf(field), ", ")))
	}

	path, _ := pathOf(field)
	literal, refused := literalOf(value, path[len(path)-1])
	if refused != "" {
		return r.violation(where, fmt.Sprintf("is given %s, which it cannot hold", value))
	}

	// ADR 9: the contract cannot tell a field carrying its zero value from one
	// that was never set, so a case saying a field is absent writes nothing.
	if reflect.ValueOf(literal.Interface()).IsZero() {
		return r.violation(where, fmt.Sprintf("is given %s, which no event can be told from carrying nothing: leave the field out to say it is absent", value))
	}
	return nil
}

func (r Rule) awaits(part string, subject Case) error {
	if subject.Expect == DoesNotMatch {
		switch {
		case subject.Severity != "":
			return r.violation(part+".severity", "is expected of a case that does not match, and only a match carries one")
		case len(subject.Evidence) > 0:
			return r.violation(part+".evidence", "is expected of a case that does not match, and only a match carries any")
		}
		return nil
	}

	if subject.Severity != "" {
		if _, declared := severities[subject.Severity]; !declared {
			return r.violation(part+".severity", fmt.Sprintf("is %q, which is not one of low, medium, high, critical", subject.Severity))
		}
	}
	for index, field := range subject.Evidence {
		if _, declared := KindOf(field); !declared {
			return r.violation(fmt.Sprintf("%s.evidence[%d]", part, index), "is not a field the contract declares")
		}
	}
	return nil
}

// What the rule says about the event the case describes, against what the case
// says it should say.
//
// A pure function of a compiled rule and a case, the way deciding is a pure
// function of a rule and an event: the event is built from the contract's own
// descriptors, nothing is read from anywhere, and the answer is the one the
// engine gives on the same event.
func (p *Program) Check(subject Case) *Failure {
	match, held := p.Decide(p.describes(subject))

	if held != (subject.Expect == Matches) {
		if held {
			return p.failed(subject, fmt.Sprintf("the rule matched, on %s", strings.Join(evidenced(match.Evidence), ", ")))
		}
		return p.failed(subject, "the rule did not match")
	}
	if !held {
		return nil
	}

	if subject.Severity != "" && match.Rule.Severity != subject.Severity {
		return p.failed(subject, fmt.Sprintf("the rule is %s and the case expects %s", match.Rule.Severity, subject.Severity))
	}
	if len(subject.Evidence) > 0 {
		expected := named(subject.Evidence)
		if read := evidenced(match.Evidence); !slices.Equal(read, expected) {
			return p.failed(subject, fmt.Sprintf("the match is evidenced by %s and the case expects %s",
				strings.Join(read, ", "), strings.Join(expected, ", ")))
		}
	}
	return nil
}

// The event a case describes: the class comes from the rule, and every field the
// case names is set along the path compilation already resolved. Nothing is
// refused here, because `Accepts` refused it where it was written.
func (p *Program) describes(subject Case) *eventv1.Event {
	record := &eventv1.Event{EventClass: p.rule.Class}
	message := record.ProtoReflect()

	for _, field := range slices.Sorted(maps.Keys(subject.Event)) {
		path, declared := pathOf(field)
		if !declared {
			continue
		}
		leaf := path[len(path)-1]
		literal, refused := literalOf(subject.Event[field], leaf)
		if refused != "" {
			continue
		}

		held := message
		for _, step := range path[:len(path)-1] {
			held = held.Mutable(step).Message()
		}
		held.Set(leaf, literal)
	}
	return record
}

func (p *Program) failed(subject Case, reason string) *Failure {
	return &Failure{Rule: p.rule.ID, Case: subject.Name, Reason: reason}
}

// The fields a match was evidenced by, each named once and in one order, so that
// what a case expects and what the rule read compare as sets.
func evidenced(evidence []Evidence) []string {
	fields := make([]Field, 0, len(evidence))
	for _, seen := range evidence {
		fields = append(fields, seen.Field)
	}
	return named(fields)
}

func named(fields []Field) []string {
	written := make([]string, 0, len(fields))
	for _, field := range fields {
		written = append(written, string(field))
	}
	slices.Sort(written)
	return slices.Compact(written)
}

func written[T ~string](values []T) string {
	names := make([]string, 0, len(values))
	for _, value := range values {
		names = append(names, string(value))
	}
	return strings.Join(names, " or ")
}
