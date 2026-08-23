package detection

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// A rule resolved against the contract once, so that deciding an event is a
// walk of a tree rather than a lookup of a name: every field is a descriptor,
// every literal already holds the type its field holds, and a long list is a
// set. Nothing here is decided again per event.
type Program struct {
	rule   Rule
	root   node
	fields []Field
}

func (p *Program) Rule() Rule { return p.rule }

// Every field the program reads, sorted and without repetition.
func (p *Program) Fields() []Field { return slices.Clone(p.fields) }

// The compiled form written back out, which is what a refusal quotes and what
// answers "what did this rule become" without reading the tree.
func (p *Program) String() string { return p.root.String() }

// Turn a written rule into what runs on an event.
//
// The rule is validated first, so nothing the domain refuses reaches a hot path.
// What compilation adds is what only the contract's own types can answer:
// whether a number fits the field it is compared against, and whether what the
// rule asks for can hold at all.
func Compile(rule Rule) (*Program, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}

	read := make(map[Field]struct{})
	root, err := rule.compile("match", rule.Match, read)
	if err != nil {
		return nil, err
	}
	if err := rule.satisfiable("match", root); err != nil {
		return nil, err
	}

	fields := make([]Field, 0, len(read))
	for field := range read {
		fields = append(fields, field)
	}
	slices.Sort(fields)

	return &Program{rule: rule, root: root, fields: fields}, nil
}

// The compiled shapes, closed the way the written ones are: whatever evaluates
// a program has to answer for every shape there is.
type node interface {
	fmt.Stringer
	node()
}

type conjunction struct{ terms []node }
type disjunction struct{ terms []node }
type negation struct{ term node }

// One question about one field, resolved: the path walks the event down to the
// leaf, and the literals hold the leaf's own type.
type comparison struct {
	field    Field
	path     []protoreflect.FieldDescriptor
	operator Operator
	literals []protoreflect.Value
	member   map[any]struct{}
}

func (conjunction) node() {}
func (disjunction) node() {}
func (negation) node()    {}
func (comparison) node()  {}

func (r Rule) compile(part string, expression Expression, read map[Field]struct{}) (node, error) {
	switch term := expression.(type) {
	case Predicate:
		return r.compareOn(part+"."+string(term.Field), term, read)
	case Not:
		inner, err := r.compile(part+".not", term.Term, read)
		if err != nil {
			return nil, err
		}
		return negation{term: inner}, nil
	case All:
		terms, err := r.compileTerms(part+".all", term.Terms, read)
		if err != nil {
			return nil, err
		}
		return conjunction{terms: terms}, nil
	case Any:
		terms, err := r.compileTerms(part+".any", term.Terms, read)
		if err != nil {
			return nil, err
		}
		return disjunction{terms: terms}, nil
	default:
		return nil, r.violation(part, fmt.Sprintf("is a %T, which is not part of the rule language", expression))
	}
}

func (r Rule) compileTerms(part string, terms []Expression, read map[Field]struct{}) ([]node, error) {
	compiled := make([]node, 0, len(terms))
	for index, term := range terms {
		term, err := r.compile(fmt.Sprintf("%s[%d]", part, index), term, read)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, term)
	}
	return compiled, nil
}

func (r Rule) compareOn(where string, predicate Predicate, read map[Field]struct{}) (node, error) {
	path, declared := pathOf(predicate.Field)
	if !declared {
		return nil, r.violation(where, "is not a field the contract declares")
	}
	read[predicate.Field] = struct{}{}

	compiled := comparison{field: predicate.Field, path: path, operator: predicate.Operator}
	leaf := path[len(path)-1]
	for _, value := range predicate.Values {
		literal, refused := literalOf(value, leaf)
		if refused != "" {
			return nil, r.violation(where, refused)
		}
		compiled.literals = append(compiled.literals, literal)
	}

	// A membership test is asked once per event and a rule may list four
	// thousand addresses, so the list becomes a set here and never again.
	if predicate.Operator == OneOf {
		compiled.member = make(map[any]struct{}, len(compiled.literals))
		for _, literal := range compiled.literals {
			compiled.member[literal.Interface()] = struct{}{}
		}
	}
	return compiled, nil
}

// A literal is compiled into the type its field holds, or the rule is refused.
// A number the field can never carry compares false against every event, and a
// rule that is quiet is worse than one that is wrong: its author is told here
// rather than left wondering later why nothing ever fires.
func literalOf(value Value, leaf protoreflect.FieldDescriptor) (protoreflect.Value, string) {
	switch leaf.Kind() {
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(value.Text()), ""
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(value.Truth()), ""
	case protoreflect.EnumKind:
		number, declared := enumOf(leaf.Enum(), value.Text())
		if !declared {
			return protoreflect.Value{}, fmt.Sprintf("is compared against %s, which the contract does not declare", value)
		}
		return protoreflect.ValueOfEnum(number), ""
	}
	return numberOf(value, leaf)
}

// The widest whole number a rule can state exactly. Past it a float64 counts in
// steps larger than one, so the literal and the number somebody wrote stop
// being the same number.
const exactly = 1 << 53

func numberOf(value Value, leaf protoreflect.FieldDescriptor) (protoreflect.Value, string) {
	number := value.Number()

	switch leaf.Kind() {
	case protoreflect.FloatKind:
		if math.Abs(number) > math.MaxFloat32 {
			return protoreflect.Value{}, fmt.Sprintf("is compared against %s, which is wider than the field holds", value)
		}
		return protoreflect.ValueOfFloat32(float32(number)), ""
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(number), ""
	}

	if math.IsNaN(number) || math.IsInf(number, 0) || number != math.Trunc(number) {
		return protoreflect.Value{}, fmt.Sprintf("is compared against %s, and the field holds whole numbers", value)
	}
	if low, high := bounds(leaf.Kind()); number < low || number > high {
		return protoreflect.Value{}, fmt.Sprintf("is compared against %s, and the field holds whole numbers from %s to %s",
			value, whole(low), whole(high))
	}

	switch leaf.Kind() {
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(number)), ""
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(number)), ""
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(number)), ""
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(number)), ""
	}
	return protoreflect.Value{}, fmt.Sprintf("holds %s, which no rule can compare against", leaf.Kind())
}

func bounds(kind protoreflect.Kind) (low, high float64) {
	switch kind {
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return math.MinInt32, math.MaxInt32
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return 0, math.MaxUint32
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return 0, exactly
	}
	return -exactly, exactly
}

func whole(value float64) string { return strconv.FormatFloat(value, 'f', -1, 64) }

// The number a written choice stands for.
func enumOf(enumeration protoreflect.EnumDescriptor, name string) (protoreflect.EnumNumber, bool) {
	values := enumeration.Values()
	for index := range values.Len() {
		value := values.Get(index)
		if shortName(enumeration, value) == name {
			return value.Number(), true
		}
	}
	return 0, false
}

func (c conjunction) String() string { return grouped(c.terms, " and ") }
func (d disjunction) String() string { return grouped(d.terms, " or ") }
func (n negation) String() string    { return "not " + n.term.String() }

func grouped(terms []node, with string) string {
	written := make([]string, 0, len(terms))
	for _, term := range terms {
		written = append(written, term.String())
	}
	return "(" + strings.Join(written, with) + ")"
}

func (c comparison) String() string {
	if c.operator == Present {
		return fmt.Sprintf("%s %s", c.field, c.operator)
	}

	written := make([]string, 0, len(c.literals))
	for _, literal := range c.literals {
		written = append(written, c.wrote(literal))
	}
	if c.operator == OneOf {
		return fmt.Sprintf("%s %s [%s]", c.field, c.operator, strings.Join(written, ", "))
	}
	return fmt.Sprintf("%s %s %s", c.field, c.operator, written[0])
}

// A literal is written back the way a rule writes it: a choice under the short
// name the contract declares, text in quotes, a number as a number.
func (c comparison) wrote(literal protoreflect.Value) string {
	leaf := c.path[len(c.path)-1]
	switch leaf.Kind() {
	case protoreflect.StringKind:
		return strconv.Quote(literal.String())
	case protoreflect.BoolKind:
		return strconv.FormatBool(literal.Bool())
	case protoreflect.EnumKind:
		value := leaf.Enum().Values().ByNumber(literal.Enum())
		if value == nil {
			return strconv.FormatInt(int64(literal.Enum()), 10)
		}
		return shortName(leaf.Enum(), value)
	}
	return fmt.Sprintf("%v", literal.Interface())
}
