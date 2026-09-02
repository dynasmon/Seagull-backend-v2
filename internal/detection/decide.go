package detection

import (
	"fmt"
	"slices"

	"google.golang.org/protobuf/reflect/protoreflect"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// What a rule and an event came to, when they came to something: the rule that
// decided it, and what in the event decided it. The event is not held here
// because the caller has it, and neither is the ruleset, because naming the set
// a rule came from belongs to whatever records a detection.
type Match struct {
	Rule     Rule
	Evidence []Evidence

	Counted    Counted
	Correlated Correlated
}

// One question the rule asked of the event, and what the event answered. What
// was asked in full stays in the rule, and the rule is held by a ruleset named
// by its own content, so what is kept here is what only the event can say.
type Evidence struct {
	Field    Field
	Operator Operator
	Negated  bool

	// Written the way a rule writes a literal, so that an analyst reads the
	// event back in the language the rule was written in.
	Held   string
	Absent bool
}

func (e Evidence) String() string {
	asked := string(e.Operator)
	if e.Negated {
		asked = "not " + asked
	}
	if e.Absent {
		return fmt.Sprintf("%s %s, and the event does not carry it", e.Field, asked)
	}
	return fmt.Sprintf("%s %s, and the event holds %s", e.Field, asked, e.Held)
}

// Whether an event answers the rule, and what in it answered.
//
// A pure function of a rule and an event: it reads nothing but the message in
// front of it, keeps nothing between calls, does no I/O and cannot fail.
// Counting, windows and suppression are not here and are not missing — they are
// state, and a rule that needs more than the event in front of it is a
// different kind of rule.
//
// A rule reads one class of event, which is what puts it on a route rather than
// in front of everything on the backbone. Asked about another class it answers
// no: the class is structural, and a rule for one kind of event has nothing to
// say about another.
func (p *Program) Decide(record *eventv1.Event) (Match, bool) {
	if record == nil || record.GetEventClass() != p.rule.Class {
		return Match{}, false
	}
	if len(p.stages) > 0 {
		reached, evidence := p.Satisfied(record)
		return Match{Rule: p.rule, Evidence: evidence}, reached.Any()
	}

	// The tree is walked once to decide and again only when it held, which is
	// what keeps the common answer — no — free of allocation.
	message := record.ProtoReflect()
	if !p.root.holds(message, nil, false) {
		return Match{}, false
	}

	evidence := make([]Evidence, 0, len(p.fields))
	p.root.holds(message, &evidence, false)
	return Match{Rule: p.rule, Evidence: evidence}, true
}

// Which stages of the sequence this event satisfies, and what in it satisfied
// them.
//
// As pure as deciding a match is, and for the same reason: a stage asks of one
// event exactly what a rule without a sequence asks of one event. Which stage
// comes after which is not asked here — that is the order, and the order is the
// one part answered from state.

func (p *Program) Satisfied(record *eventv1.Event) (Stages, []Evidence) {
	if record == nil || record.GetEventClass() != p.rule.Class {
		return 0, nil
	}

	message := record.ProtoReflect()
	var reached Stages
	for index, stage := range p.stages {
		if stage.root.holds(message, nil, false) {
			reached = reached.Add(index)
		}
	}
	if !reached.Any() {
		return 0, nil
	}

	evidence := make([]Evidence, 0, len(p.fields))
	for index, stage := range p.stages {
		if reached.Has(index) {
			stage.root.holds(message, &evidence, false)
		}
	}
	return reached, evidence
}

func (p *Program) Stages() []string {
	names := make([]string, 0, len(p.stages))
	for _, stage := range p.stages {
		names = append(names, stage.name)
	}
	return names
}

// What this event binds the rule's group fields to, in the order the rule
// names them. Reading it is the same walk deciding is, so a field the event
// does not carry binds to absent rather than to nothing.
func (p *Program) Group(record *eventv1.Event) []Binding {
	if len(p.grouped) == 0 {
		return nil
	}

	message := record.ProtoReflect()
	group := make([]Binding, 0, len(p.grouped))
	for _, grouped := range p.grouped {
		value, carried := read(message, grouped.path)
		if !carried {
			group = append(group, Binding{Field: grouped.field, Absent: true})
			continue
		}
		group = append(group, Binding{Field: grouped.field, Value: plain(grouped.path[len(grouped.path)-1], value)})
	}
	return group
}

func (c conjunction) holds(record protoreflect.Message, into *[]Evidence, negated bool) bool {
	for _, term := range c.terms {
		if !term.holds(record, into, negated) {
			return false
		}
	}
	return true
}

// The branch that held is the whole reason, so the ones tried before it are
// dropped and the one that answered is read again for what it saw. A
// disjunction that holds nowhere keeps every branch instead: under a negation,
// all of them failing is exactly why it holds.
func (d disjunction) holds(record protoreflect.Message, into *[]Evidence, negated bool) bool {
	mark := 0
	if into != nil {
		mark = len(*into)
	}

	for _, term := range d.terms {
		if !term.holds(record, into, negated) {
			continue
		}
		if into != nil {
			*into = (*into)[:mark]
			term.holds(record, into, negated)
		}
		return true
	}
	return false
}

// Negation is a polarity carried down to the questions underneath rather than
// an answer thrown away here, so evidence can say what the rule asked of a
// field as well as what the event held in it.
func (n negation) holds(record protoreflect.Message, into *[]Evidence, negated bool) bool {
	return !n.term.holds(record, into, !negated)
}

// Evidence is a set of what the event said, not a list of what the rule asked.
// A rule refusing three private prefixes asks three questions of one field and
// gets one answer, and what was asked in full is not kept here — so the same
// observation gathered again is the same observation, and writing it down twice
// would say nothing and read like a fault.
func (c comparison) holds(record protoreflect.Message, into *[]Evidence, negated bool) bool {
	value, carried := read(record, c.path)
	if into != nil {
		if seen := c.saw(value, carried, negated); !slices.Contains(*into, seen) {
			*into = append(*into, seen)
		}
	}
	return c.answered(value, carried)
}

// An absent field answers no question. Every comparison against it is false,
// which is what makes negation say the useful thing: a rule asking that a field
// is not something also holds when the event does not carry the field at all.
func (c comparison) answered(value protoreflect.Value, carried bool) bool {
	if !carried {
		return false
	}
	if c.operator == Present {
		return true
	}
	held, decided := answers(value, c)
	return held && decided
}

// The walk down to the leaf, along the descriptors compilation resolved. A
// message that is not set stops it: the event does not carry the field, which
// the contract does not distinguish from carrying the zero value, so the rule
// language says it once and says it in `present`.
func read(record protoreflect.Message, path []protoreflect.FieldDescriptor) (protoreflect.Value, bool) {
	message := record
	for _, step := range path[:len(path)-1] {
		if !message.Has(step) {
			return protoreflect.Value{}, false
		}
		message = message.Get(step).Message()
	}

	leaf := path[len(path)-1]
	if !message.Has(leaf) {
		return protoreflect.Value{}, false
	}
	return message.Get(leaf), true
}

func (c comparison) saw(value protoreflect.Value, carried, negated bool) Evidence {
	seen := Evidence{Field: c.field, Operator: c.operator, Negated: negated, Absent: !carried}
	if carried {
		seen.Held = c.wrote(value)
	}
	return seen
}
