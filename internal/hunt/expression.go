package hunt

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// How much one question may carry. A literal longer than this is a document and
// a list longer than it is a dataset, and neither is a term of a query.
const (
	maxValuesPerPredicate = 256
	maxValueBytes         = 512
)

// What one question asks of one field. The set is closed because the server
// compiles it into a read of the store and has to be able to cost every shape
// there is; an operator a caller can invent is a query nobody can bound.
//
// There is no regular expression and no wildcard, for the same reason the rule
// language has none: a pattern hands the caller control of how much of the store
// a question reads.
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

var accepts = map[Operator][]Kind{
	Equals:     {Text, Number, Truth, Choice, Instant},
	OneOf:      {Text, Number, Choice},
	Contains:   {Text},
	StartsWith: {Text},
	EndsWith:   {Text},
	Above:      {Number, Instant},
	AtLeast:    {Number, Instant},
	Below:      {Number, Instant},
	AtMost:     {Number, Instant},
	Present:    {Text, Number, Truth, Choice, Instant},
}

// What may be asked of a column the store keeps as a list. The store holds one
// array per leaf, so a question can ask whether the array carries a value and
// cannot ask how one entry compares to another.
var acceptsList = []Operator{Equals, OneOf, Present}

// Every operator there is, sorted, so a refusal can say what was available.
func Operators() []Operator {
	known := make([]Operator, 0, len(accepts))
	for operator := range accepts {
		known = append(known, operator)
	}
	slices.Sort(known)
	return known
}

func (o Operator) known() bool {
	_, declared := accepts[o]
	return declared
}

func (o Operator) asks(kind Kind) bool {
	return slices.Contains(accepts[o], kind)
}

// How many literals an operator reads. `Present` asks whether the record carries
// the field at all, so it reads none.
func (o Operator) takes() (minimum, maximum int) {
	switch o {
	case Present:
		return 0, 0
	case OneOf:
		return 1, maxValuesPerPredicate
	default:
		return 1, 1
	}
}

// A literal in a query, held to what the field it is asked of carries.
type Value struct {
	kind    Kind
	text    string
	number  float64
	whole   int64
	exact   bool
	truth   bool
	instant time.Time
}

func (v Value) Kind() Kind { return v.kind }

// A number written without a fraction is kept as one, so a comparison against an
// unsigned column stays exact past the range a float can name: v1's identifiers
// were text and never had to answer this, and a sequence counter does.
func (v Value) Whole() (int64, bool) { return v.whole, v.exact }

func (v Value) Text() string       { return v.text }
func (v Value) Number() float64    { return v.number }
func (v Value) Truth() bool        { return v.truth }
func (v Value) Instant() time.Time { return v.instant }

func (v Value) String() string {
	switch v.kind {
	case Number:
		if v.exact {
			return strconv.FormatInt(v.whole, 10)
		}
		return strconv.FormatFloat(v.number, 'g', -1, 64)
	case Truth:
		return strconv.FormatBool(v.truth)
	case Instant:
		return v.instant.Format(time.RFC3339Nano)
	default:
		return strconv.Quote(v.text)
	}
}

// Read a literal the way it was written and hold it to the field's kind. A
// choice arrives as a person says it and is held to the values the contract
// declares, so a misspelled outcome is refused rather than matching nothing.
func literal(entry held, written string) (Value, error) {
	if len(written) > maxValueBytes {
		return Value{}, fmt.Errorf("a literal may be at most %d bytes and this one is %d", maxValueBytes, len(written))
	}

	switch entry.kind {
	case Number:
		if whole, err := strconv.ParseInt(written, 10, 64); err == nil {
			return Value{kind: Number, number: float64(whole), whole: whole, exact: true}, nil
		}
		number, err := strconv.ParseFloat(written, 64)
		if err != nil {
			return Value{}, fmt.Errorf("%q is not a number", written)
		}
		return Value{kind: Number, number: number}, nil
	case Truth:
		truth, err := strconv.ParseBool(written)
		if err != nil {
			return Value{}, fmt.Errorf("%q is not true or false", written)
		}
		return Value{kind: Truth, truth: truth}, nil
	case Instant:
		instant, err := time.Parse(time.RFC3339, written)
		if err != nil {
			return Value{}, fmt.Errorf("%q is not an RFC 3339 instant", written)
		}
		return Value{kind: Instant, instant: instant.UTC()}, nil
	case Choice:
		if !slices.Contains(entry.choices, written) {
			return Value{}, fmt.Errorf("%q is not one of %s", written, strings.Join(entry.choices, ", "))
		}
		return Value{kind: Choice, text: written}, nil
	default:
		return Value{kind: Text, text: written}, nil
	}
}

// The boolean shape a query matches with, closed the same way the rule language
// is closed: the compiler switches over every form there is, and a form that can
// grow behind it is a form that reads differently in two places.
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

// The term must not hold.
type Not struct{ Term Expression }

func (Predicate) expression() {}
func (All) expression()       {}
func (Any) expression()       {}
func (Not) expression()       {}

func (p Predicate) String() string {
	if p.Operator == Present {
		return string(p.Field) + " present"
	}
	written := make([]string, 0, len(p.Values))
	for _, value := range p.Values {
		written = append(written, value.String())
	}
	return fmt.Sprintf("%s %s %s", p.Field, p.Operator, strings.Join(written, ", "))
}

func (a All) String() string { return joined(a.Terms, " and ") }
func (a Any) String() string { return joined(a.Terms, " or ") }
func (n Not) String() string { return "not " + render(n.Term) }

func joined(terms []Expression, separator string) string {
	written := make([]string, 0, len(terms))
	for _, term := range terms {
		written = append(written, render(term))
	}
	return "(" + strings.Join(written, separator) + ")"
}

func render(term Expression) string {
	if written, ok := term.(fmt.Stringer); ok {
		return written.String()
	}
	return "?"
}
