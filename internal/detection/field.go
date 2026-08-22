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
}

var vocabulary = sync.OnceValue(buildVocabulary)

func buildVocabulary() map[Field]held {
	fields := make(map[Field]held)
	describe((&eventv1.Event{}).ProtoReflect().Descriptor(), "", fields, 0)
	return fields
}

func describe(descriptor protoreflect.MessageDescriptor, prefix string, into map[Field]held, depth int) {
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

		switch field.Kind() {
		case protoreflect.StringKind:
			into[Field(path)] = held{kind: Text}
		case protoreflect.BoolKind:
			into[Field(path)] = held{kind: Truth}
		case protoreflect.EnumKind:
			into[Field(path)] = held{kind: Choice, choices: choicesOf(field.Enum())}
		case protoreflect.MessageKind, protoreflect.GroupKind:
			if strings.HasPrefix(string(field.Message().FullName()), "google.protobuf.") {
				continue
			}
			describe(field.Message(), path+".", into, depth+1)
		default:
			if numeric(field.Kind()) {
				into[Field(path)] = held{kind: Number}
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
	prefix := upperSnake(string(enumeration.Name())) + "_"

	values := enumeration.Values()
	named := make([]string, 0, values.Len())
	for index := range values.Len() {
		name := string(values.Get(index).Name())
		named = append(named, strings.ToLower(strings.TrimPrefix(name, prefix)))
	}
	return named
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

// The body a class carries is named after the class: EVENT_CLASS_AUTHENTICATION
// carries `authentication`.
func bodyOf(class eventv1.EventClass) string {
	name, declared := eventv1.EventClass_name[int32(class)]
	if !declared {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(name, "EVENT_CLASS_"))
}

// Whether a rule for this class can reach the field at all. Everything outside
// a body is common to every event; a body belongs to its own class, and a rule
// that reaches into another one would never match — which is worse than being
// refused, because it fails silently.
func AddressableBy(field Field, class eventv1.EventClass) bool {
	if _, declared := KindOf(field); !declared {
		return false
	}

	root, _, _ := strings.Cut(string(field), ".")
	if _, isBody := bodies()[root]; !isBody {
		return true
	}
	return root == bodyOf(class)
}
