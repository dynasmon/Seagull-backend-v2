package detection

import (
	"math"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The plain forms a value is written in, at their longest: a float64 in its
// shortest exact form, a truth, and an enumeration number no build declares.
const (
	longestNumber     = len("-2.2250738585072014e-308")
	longestTruth      = len("false")
	longestUndeclared = len("-2147483648")
)

var longestInstant = time.Unix(-1, 999_999_999).UTC()

// The most bytes a detection of this program can encode to, measured by making
// the heaviest one it could: every question it asks answered as evidence at the
// longest its field is written in, every field it groups by at its longest, each
// stage told by the longest agent and event names, and the event it is decided
// from at the longest the contract lets its origin be.
func (p *Program) Heaviest() int {
	asked := make(map[question]struct{})
	if p.root != nil {
		p.root.asks(false, asked)
	}
	for _, stage := range p.stages {
		stage.root.asks(false, asked)
	}

	match := Match{Rule: p.rule}
	for one := range asked {
		match.Evidence = append(match.Evidence, Evidence{
			Field: one.field, Operator: one.operator, Negated: one.negated, Held: strings.Repeat("x", heldAtMost(one.field)),
		})
	}
	group := make([]Binding, 0, len(p.grouped))
	for _, grouped := range p.grouped {
		group = append(group, Binding{Field: grouped.field, Value: strings.Repeat("x", valueAtMost(grouped.field))})
	}
	switch {
	case p.Counts():
		match.Counted = Counted{Group: group, Count: MaxCount, First: longestInstant, Saturated: true}
	case p.Correlates():
		match.Correlated = Correlated{Group: group, ClockSpread: time.Duration(math.MaxInt64)}
		for _, stage := range p.stages {
			match.Correlated.Stages = append(match.Correlated.Stages, Satisfied{
				Name: stage.name, Agent: longest("origin.agent_id"), Event: longest("event_id"), At: longestInstant,
			})
		}
	}
	return proto.Size(match.Detected(strings.Repeat("x", event.MaxEventIDLength), heaviestEvent(p.rule.Class), longestInstant))
}

func heaviestEvent(class eventv1.EventClass) *eventv1.Event {
	record := &eventv1.Event{
		EventId:    longest("event_id"),
		EventClass: class,
		Time:       &eventv1.Timestamps{EventTime: timestamppb.New(longestInstant)},
	}
	for _, field := range Fields() {
		if kind, _ := KindOf(field); kind == Text && strings.HasPrefix(string(field), "origin.") {
			path, _ := pathOf(field)
			place(record.ProtoReflect(), path, protoreflect.ValueOfString(longest(field)))
		}
	}
	return record
}

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

func longest(field Field) string { return strings.Repeat("x", longestText(field)) }

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
