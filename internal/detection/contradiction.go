package detection

import (
	"fmt"
	"math"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// A rule that can never match and a rule that matches every event are both
// rules nobody notices are wrong: one is silent and the other is noise, and
// neither says so. What can be decided from the rule alone is decided here,
// while its author is still reading it.
//
// The check proves emptiness rather than searching for it. A rule is refused
// only when two things it asks for demonstrably cannot both hold, and whatever
// cannot be decided is let through: a compiler that guesses would refuse rules
// that are fine, which is the more expensive mistake.
func (r Rule) satisfiable(part string, term node) error {
	switch term := term.(type) {
	case conjunction:
		questions := directly(term.terms, true)
		if err := r.opposed(part+".all", questions, "can never match"); err != nil {
			return err
		}
		if err := r.narrowed(part+".all", questions); err != nil {
			return err
		}
		return r.eachOf(part+".all", term.terms)
	case disjunction:
		if err := r.opposed(part+".any", directly(term.terms, false), "matches every event"); err != nil {
			return err
		}
		return r.eachOf(part+".any", term.terms)
	case negation:
		return r.satisfiable(part+".not", term.term)
	}
	return nil
}

func (r Rule) eachOf(part string, terms []node) error {
	for index, term := range terms {
		if err := r.satisfiable(fmt.Sprintf("%s[%d]", part, index), term); err != nil {
			return err
		}
	}
	return nil
}

// One comparison as a node asks it, with the negation that stands over it.
type asked struct {
	compare comparison
	negated bool
}

func (a asked) String() string {
	if a.negated {
		return "not " + a.compare.String()
	}
	return a.compare.String()
}

// The comparisons a node asks directly, with nested nodes of its own kind
// folded in because `and` and `or` are both associative. Anything else is left
// alone: what a disjunction under a conjunction settles is not settled here.
func directly(terms []node, conjunctive bool) []asked {
	var questions []asked
	for _, term := range terms {
		switch term := term.(type) {
		case comparison:
			questions = append(questions, asked{compare: term})
		case negation:
			if compare, is := term.term.(comparison); is {
				questions = append(questions, asked{compare: compare, negated: true})
			}
		case conjunction:
			if conjunctive {
				questions = append(questions, directly(term.terms, true)...)
			}
		case disjunction:
			if !conjunctive {
				questions = append(questions, directly(term.terms, false)...)
			}
		}
	}
	return questions
}

func (r Rule) opposed(part string, questions []asked, because string) error {
	polarity := make(map[string]bool, len(questions))
	for _, question := range questions {
		written := question.compare.String()
		if negated, seen := polarity[written]; seen && negated != question.negated {
			return r.violation(part, fmt.Sprintf("asks %s and also that it does not, so it %s", written, because))
		}
		polarity[written] = question.negated
	}
	return nil
}

func (r Rule) narrowed(part string, questions []asked) error {
	byField := make(map[Field][]asked)
	order := make([]Field, 0, len(questions))
	for _, question := range questions {
		field := question.compare.field
		if _, seen := byField[field]; !seen {
			order = append(order, field)
		}
		byField[field] = append(byField[field], question)
	}

	for _, field := range order {
		if reason := empty(byField[field]); reason != "" {
			return r.violation(part, reason)
		}
	}
	return nil
}

// What a conjunction leaves a single field: the values an equality still
// allows, and the range the comparisons still leave open.
type window struct {
	allowed map[any]protoreflect.Value
	from    string

	low, high         float64
	lowOpen, highOpen bool
	bounded           string
}

func empty(questions []asked) string {
	held := window{low: math.Inf(-1), high: math.Inf(1)}
	var rest []asked

	for _, question := range questions {
		switch {
		case question.compare.operator == Present:
			// Whether a field is set cannot narrow what it holds, and asking
			// for it and against it is the same question twice: both are
			// already answered above.
		case question.negated:
			rest = append(rest, question)
		case question.compare.operator == Equals, question.compare.operator == OneOf:
			if reason := held.allow(question); reason != "" {
				return reason
			}
		case ranged(question.compare.operator):
			if reason := held.limit(question); reason != "" {
				return reason
			}
		default:
			rest = append(rest, question)
		}
	}

	return held.leaves(rest)
}

func (w *window) allow(question asked) string {
	narrowed := make(map[any]protoreflect.Value, len(question.compare.literals))
	for _, literal := range question.compare.literals {
		narrowed[literal.Interface()] = literal
	}

	if w.allowed == nil {
		w.allowed, w.from = narrowed, question.String()
		return ""
	}
	kept := make(map[any]protoreflect.Value, len(narrowed))
	for key, literal := range narrowed {
		if _, allowed := w.allowed[key]; allowed {
			kept[key] = literal
		}
	}
	if len(kept) == 0 {
		return fmt.Sprintf("asks %s and %s, which nothing satisfies", w.from, question)
	}
	w.allowed, w.from = kept, w.from+" and "+question.String()
	return ""
}

func ranged(operator Operator) bool {
	switch operator {
	case Above, AtLeast, Below, AtMost:
		return true
	}
	return false
}

func (w *window) limit(question asked) string {
	against := numberIn(question.compare.literals[0])
	switch question.compare.operator {
	case Above:
		if against > w.low || (against == w.low && !w.lowOpen) {
			w.low, w.lowOpen = against, true
		}
	case AtLeast:
		if against > w.low {
			w.low, w.lowOpen = against, false
		}
	case Below:
		if against < w.high || (against == w.high && !w.highOpen) {
			w.high, w.highOpen = against, true
		}
	case AtMost:
		if against < w.high {
			w.high, w.highOpen = against, false
		}
	}

	if w.bounded == "" {
		w.bounded = question.String()
	} else {
		w.bounded += " and " + question.String()
	}
	if w.low > w.high || (w.low == w.high && (w.lowOpen || w.highOpen)) {
		return fmt.Sprintf("asks %s, which nothing satisfies", w.bounded)
	}
	return ""
}

// Whatever the equality still allows has to answer everything else the rule
// asks of the field. A question that alone rules out every remaining value is
// named; a combination of them is left alone, because a refusal that cannot
// point at two things is a refusal nobody can act on.
func (w *window) leaves(rest []asked) string {
	if w.allowed == nil {
		return conflicting(rest)
	}
	if w.bounded != "" && !w.any(func(literal protoreflect.Value) bool { return w.within(literal) }) {
		return fmt.Sprintf("asks %s and %s, which nothing satisfies", w.from, w.bounded)
	}
	for _, question := range rest {
		if !w.any(func(literal protoreflect.Value) bool { return satisfies(literal, question) }) {
			return fmt.Sprintf("asks %s and %s, which nothing satisfies", w.from, question)
		}
	}
	return ""
}

func (w *window) any(holds func(protoreflect.Value) bool) bool {
	for _, literal := range w.allowed {
		if holds(literal) {
			return true
		}
	}
	return false
}

func (w *window) within(literal protoreflect.Value) bool {
	value := numberIn(literal)
	if math.IsNaN(value) {
		return true
	}
	if value < w.low || (value == w.low && w.lowOpen) {
		return false
	}
	return value <= w.high && !(value == w.high && w.highOpen)
}

// With nothing pinning the field to a value, two affirmative prefixes still
// cannot both hold unless one of them is a prefix of the other.
func conflicting(rest []asked) string {
	for index, question := range rest {
		if question.negated {
			continue
		}
		for _, against := range rest[index+1:] {
			if against.negated || against.compare.operator != question.compare.operator {
				continue
			}
			one, other := question.compare.literals[0].String(), against.compare.literals[0].String()
			switch question.compare.operator {
			case StartsWith:
				if !strings.HasPrefix(one, other) && !strings.HasPrefix(other, one) {
					return fmt.Sprintf("asks %s and %s, which nothing satisfies", question, against)
				}
			case EndsWith:
				if !strings.HasSuffix(one, other) && !strings.HasSuffix(other, one) {
					return fmt.Sprintf("asks %s and %s, which nothing satisfies", question, against)
				}
			}
		}
	}
	return ""
}

func satisfies(literal protoreflect.Value, question asked) bool {
	held, decided := answers(literal, question.compare)
	if !decided {
		return true
	}
	return held != question.negated
}

// Whether a field holding this value answers the comparison. Presence cannot be
// decided from a value alone and is settled elsewhere; everything else is the
// same question the engine will ask of a real event.
func answers(literal protoreflect.Value, compare comparison) (held, decided bool) {
	switch compare.operator {
	case Equals:
		return literal.Interface() == compare.literals[0].Interface(), true
	case OneOf:
		_, member := compare.member[literal.Interface()]
		return member, true
	case Contains:
		return strings.Contains(literal.String(), compare.literals[0].String()), true
	case StartsWith:
		return strings.HasPrefix(literal.String(), compare.literals[0].String()), true
	case EndsWith:
		return strings.HasSuffix(literal.String(), compare.literals[0].String()), true
	}

	value, against := numberIn(literal), numberIn(compare.literals[0])
	if math.IsNaN(value) || math.IsNaN(against) {
		return false, false
	}
	switch compare.operator {
	case Above:
		return value > against, true
	case AtLeast:
		return value >= against, true
	case Below:
		return value < against, true
	case AtMost:
		return value <= against, true
	}
	return false, false
}

func numberIn(literal protoreflect.Value) float64 {
	switch held := literal.Interface().(type) {
	case int32:
		return float64(held)
	case int64:
		return float64(held)
	case uint32:
		return float64(held)
	case uint64:
		return float64(held)
	case float32:
		return float64(held)
	case float64:
		return held
	}
	return math.NaN()
}
