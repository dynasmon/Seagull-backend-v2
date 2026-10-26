package detection

import (
	"sync"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
)

// The plain forms a value is written in, at their longest: a float64 in its
// shortest exact form, a truth, and an enumeration number no build declares.
const (
	longestNumber     = len("-2.2250738585072014e-308")
	longestTruth      = len("false")
	longestUndeclared = len("-2147483648")
)

type question struct {
	field    Field
	operator Operator
	negated  bool
}

func (c conjunction) asks(negated bool, into map[question]struct{}) {
	for _, term := range c.terms {
		term.asks(negated, into)
	}
}

func (d disjunction) asks(negated bool, into map[question]struct{}) {
	for _, term := range d.terms {
		term.asks(negated, into)
	}
}

func (n negation) asks(negated bool, into map[question]struct{}) { n.term.asks(!negated, into) }

func (c comparison) asks(negated bool, into map[question]struct{}) {
	into[question{field: c.field, operator: c.operator, negated: negated}] = struct{}{}
}

// Text is written as evidence the way a rule writes a literal, and strconv.Quote
// spends four bytes on a control character and two on the quotes around it.
func heldAtMost(field Field) int {
	if kind, _ := KindOf(field); kind == Text {
		return 4*longestText(field) + 2
	}
	return valueAtMost(field)
}

func valueAtMost(field Field) int {
	kind, _ := KindOf(field)
	switch kind {
	case Text:
		return longestText(field)
	case Truth:
		return longestTruth
	case Choice:
		widest := longestUndeclared
		for _, choice := range ChoicesOf(field) {
			widest = max(widest, len(choice))
		}
		return widest
	}
	return longestNumber
}

// A text the event contract does not bound is as long as an admitted event can
// be, so a rule reading one is refused rather than trusted.
func longestText(field Field) int {
	if most, bounded := event.LongestText(string(field)); bounded {
		return most
	}
	return event.MaxEventBytes
}

var longestWritten = sync.OnceValues(func() (held, valued int) {
	for _, field := range Fields() {
		held, valued = max(held, heldAtMost(field)), max(valued, valueAtMost(field))
	}
	return held, valued
})
