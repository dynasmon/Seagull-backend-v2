package detection

import (
	"slices"
	"strconv"
)

// The boolean expression a rule matches with. The interface is closed on
// purpose: an executor has to switch over every shape there is, and a rule
// language that can grow a shape behind the executor's back is a rule language
// that evaluates differently in two places.
type Expression interface{ expression() }

// A question about one field.
type Predicate struct {
	Field    Field
	Operator Operator
	Values   []Value
}

// Every term has to hold.
type All struct{ Terms []Expression }

// At least one term has to hold.
type Any struct{ Terms []Expression }

// The term must not hold. Negation lives here rather than inside the operators,
// so there is one way to say "not" instead of one per operator: v1 carried
// `neq`, `not_in` and `not_contains` because its match was a flat map with
// nowhere to put a negation, and each of them was a second place for the same
// mistake.
type Not struct{ Term Expression }

func (Predicate) expression() {}
func (All) expression()       {}
func (Any) expression()       {}
func (Not) expression()       {}

// What a predicate asks. Every operator is decidable from one event on its own:
// nothing here counts, remembers or looks anything up, because a rule that
// needs more than the event in front of it is an aggregation, and aggregation
// is a different card and a different kind of state.
type Operator string

const (
	Equals     Operator = "equals"
	OneOf      Operator = "one_of"
	Contains   Operator = "contains"
	StartsWith Operator = "starts_with"
	EndsWith   Operator = "ends_with"
	Above      Operator = "above"
	AtLeast    Operator = "at_least"
	Below      Operator = "below"
	AtMost     Operator = "at_most"
	Present    Operator = "present"
)

// There is no regular expression here, and that is a decision rather than an
// omission: a pattern language turns evaluation cost into something a rule
// author controls, and the ingest baseline already found one identifier regular
// expression to be most of the cost of admitting an event.
var accepts = map[Operator][]Kind{
	Equals:     {Text, Number, Truth, Choice},
	OneOf:      {Text, Number, Choice},
	Contains:   {Text},
	StartsWith: {Text},
	EndsWith:   {Text},
	Above:      {Number},
	AtLeast:    {Number},
	Below:      {Number},
	AtMost:     {Number},
	Present:    {Text, Number, Truth, Choice},
}

// How many literals an operator reads. `Present` asks whether the event carries
// the field at all, so it reads none.
func (o Operator) takes() (minimum, maximum int) {
	switch o {
	case Present:
		return 0, 0
	case OneOf:
		return 1, 0 // no ceiling: an allowlist is a long list
	default:
		return 1, 1
	}
}

func (o Operator) asks(kind Kind) bool {
	for _, accepted := range accepts[o] {
		if accepted == kind {
			return true
		}
	}
	return false
}

func (o Operator) known() bool {
	_, declared := accepts[o]
	return declared
}

// Every operator the language has, sorted, so a refusal can say what was
// available instead.
func Operators() []Operator {
	known := make([]Operator, 0, len(accepts))
	for operator := range accepts {
		known = append(known, operator)
	}
	slices.Sort(known)
	return known
}

// A literal in a rule. Comparable, so two rules that say the same thing hold
// the same value and a compiled rule can be keyed on it.
type Value struct {
	kind   Kind
	text   string
	number float64
	truth  bool
}

// A choice is written the way a person says it — `failure`, not
// `OUTCOME_FAILURE` — so it arrives as text and is held to the values the
// contract declares.
func TextValue(text string) Value      { return Value{kind: Text, text: text} }
func NumberValue(number float64) Value { return Value{kind: Number, number: number} }
func TruthValue(truth bool) Value      { return Value{kind: Truth, truth: truth} }

func (v Value) Kind() Kind      { return v.kind }
func (v Value) Text() string    { return v.text }
func (v Value) Number() float64 { return v.number }
func (v Value) Truth() bool     { return v.truth }

func (v Value) String() string {
	switch v.kind {
	case Number:
		return strconv.FormatFloat(v.number, 'g', -1, 64)
	case Truth:
		return strconv.FormatBool(v.truth)
	default:
		return strconv.Quote(v.text)
	}
}

// Whether a literal can answer a question about a field of this kind. A choice
// is named in text; everything else answers for itself.
func (v Value) fits(kind Kind) bool {
	if kind == Choice {
		return v.kind == Text
	}
	return v.kind == kind
}
