package detection

import (
	"slices"
	"strings"
	"sync"

	"google.golang.org/protobuf/reflect/protoreflect"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// A field a rule matches on: the path of a scalar the event contract declares,
// written from the event down — `origin.host.hostname`,
// `authentication.user.name`.
//
// There is no dictionary between a rule and the contract. v1 had one, mapping
// rule-facing names to storage columns, and the fields that did not fit ended up
// addressed through a JSON bag; ADR 3 removed the bag by making the contract the
// model, so the vocabulary is the contract itself and cannot drift from it.
type Field string

// What a field holds, which decides what can be asked of it.
type Kind string

const (
	Text   Kind = "text"
	Number Kind = "number"
	Truth  Kind = "truth"
	Choice Kind = "choice" // one of a set the contract declares
)

// Time is not addressable. A timestamp is not something a stateless rule
// compares to a literal, and a window is not a predicate: both arrive with
// aggregation, and a field that cannot be used well is better left out than
// left in for a rule to trip over.
const maxDepth = 8

type held struct {
	kind    Kind
	choices []string
	path    []protoreflect.FieldDescriptor
}

var vocabulary = sync.OnceValue(buildVocabulary)

func buildVocabulary() map[Field]held {
	fields := make(map[Field]held)
	describe((&eventv1.Event{}).ProtoReflect().Descriptor(), "", nil, fields, 0)
	return fields
}

// The walk records how to reach a field as well as what it holds, so that
// resolving a name to the contract happens once for the life of the process
// rather than once per event.
func describe(descriptor protoreflect.MessageDescriptor, prefix string, trail []protoreflect.FieldDescriptor, into map[Field]held, depth int) {
	if depth > maxDepth {
		return
	}

	fields := descriptor.Fields()
	for index := range fields.Len() {
		field := fields.Get(index)
		if field.IsList() || field.IsMap() {
			continue
		}
		path := prefix + string(field.Name())
		reach := append(slices.Clone(trail), field)

		switch field.Kind() {
		case protoreflect.StringKind:
			into[Field(path)] = held{kind: Text, path: reach}
		case protoreflect.BoolKind:
			into[Field(path)] = held{kind: Truth, path: reach}
		case protoreflect.EnumKind:
			into[Field(path)] = held{kind: Choice, choices: choicesOf(field.Enum()), path: reach}
		case protoreflect.MessageKind, protoreflect.GroupKind:
			if strings.HasPrefix(string(field.Message().FullName()), "google.protobuf.") {
				continue
			}
			describe(field.Message(), path+".", reach, into, depth+1)
		default:
			if numeric(field.Kind()) {
				into[Field(path)] = held{kind: Number, path: reach}
			}
		}
	}
}

func numeric(kind protoreflect.Kind) bool {
	switch kind {
	case protoreflect.Int32Kind, protoreflect.Int64Kind,
		protoreflect.Uint32Kind, protoreflect.Uint64Kind,
		protoreflect.Sint32Kind, protoreflect.Sint64Kind,
		protoreflect.Fixed32Kind, protoreflect.Fixed64Kind,
		protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind,
		protoreflect.FloatKind, protoreflect.DoubleKind:
		return true
	}
	return false
}

// A rule names a choice the way a person would say it — `failure`, not
// `OUTCOME_FAILURE`. The contract prefixes every value of an enumeration with
// the enumeration's own name, and the suite holds it to that rather than
// trusting it.
func choicesOf(enumeration protoreflect.EnumDescriptor) []string {
	values := enumeration.Values()
	named := make([]string, 0, values.Len())
	for index := range values.Len() {
		named = append(named, shortName(enumeration, values.Get(index)))
	}
	return named
}

func shortName(enumeration protoreflect.EnumDescriptor, value protoreflect.EnumValueDescriptor) string {
	prefix := upperSnake(string(enumeration.Name())) + "_"
	return strings.ToLower(strings.TrimPrefix(string(value.Name()), prefix))
}

func upperSnake(name string) string {
	var snake strings.Builder
	for index, letter := range name {
		if index > 0 && letter >= 'A' && letter <= 'Z' {
			snake.WriteByte('_')
		}
		snake.WriteRune(letter)
	}
	return strings.ToUpper(snake.String())
}

func KindOf(field Field) (Kind, bool) {
	entry, declared := vocabulary()[field]
	return entry.kind, declared
}

// How to reach the field from the event: every message on the way down and the
// leaf itself.
func pathOf(field Field) ([]protoreflect.FieldDescriptor, bool) {
	entry, declared := vocabulary()[field]
	return entry.path, declared
}

// The values a choice field accepts, in the order the contract declares them.
func ChoicesOf(field Field) []string {
	return slices.Clone(vocabulary()[field].choices)
}

// Every field a rule may match on, sorted, so a refusal can say what was
// available instead.
func Fields() []Field {
	known := vocabulary()
	fields := make([]Field, 0, len(known))
	for field := range known {
		fields = append(fields, field)
	}
	slices.Sort(fields)
	return fields
}

// Every field that belongs to one class rather than to every event: the members
// of the contract's oneof, by name.
var bodies = sync.OnceValue(func() map[string]struct{} {
	descriptor := (&eventv1.Event{}).ProtoReflect().Descriptor()
	named := make(map[string]struct{})

	oneofs := descriptor.Oneofs()
	for index := range oneofs.Len() {
		fields := oneofs.Get(index).Fields()
		for member := range fields.Len() {
			named[string(fields.Get(member).Name())] = struct{}{}
		}
	}
	return named
})

// Whether a rule for this class can reach the field at all. Everything outside
// a body is common to every event; a body belongs to its own class, and a rule
// that reaches into another one would never match — which is worse than being
// refused, because it fails silently.
func AddressableBy(field Field, class eventv1.EventClass) bool {
	if _, declared := KindOf(field); !declared {
		return false
	}

	// The body a class carries is named after the class, so the name a rule
	// writes the class under is also the root of the fields it may reach.
	root, _, _ := strings.Cut(string(field), ".")
	if _, isBody := bodies()[root]; !isBody {
		return true
	}
	return root == className(class)
}
