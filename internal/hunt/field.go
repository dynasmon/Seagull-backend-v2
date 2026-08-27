package hunt

import (
	"slices"
	"strings"
	"sync"

	"google.golang.org/protobuf/reflect/protoreflect"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// Which stored record a question is asked of. Each one is a projection of a
// contract message, so the vocabulary a query is written in is that contract and
// there is nothing in between: v1 mapped caller-facing names onto storage
// columns and the fields that did not fit ended up in a JSON bag nothing could
// query.
type Dataset string

const (
	Events     Dataset = "events"
	Detections Dataset = "detections"
)

func Datasets() []Dataset { return []Dataset{Detections, Events} }

// A field a query asks about: the path of a leaf the contract declares, written
// from the record down — `authentication.user.name`, `rule.id`.
type Field string

// What a field holds, which decides what can be asked of it.
type Kind string

const (
	Text    Kind = "text"
	Number  Kind = "number"
	Truth   Kind = "truth"
	Choice  Kind = "choice"
	Instant Kind = "instant"
)

// A rule cannot address time and a query has to. A rule decides one event
// against a literal; a hunt is a window over a timeline before it is anything
// else, and the store keeps every instant the contract carries.
const timestamp = "google.protobuf.Timestamp"

const maxDepth = 8

type held struct {
	kind     Kind
	repeated bool
	choices  []string
}

var vocabularies = sync.OnceValue(func() map[Dataset]map[Field]held {
	return map[Dataset]map[Field]held{
		Events:     describe((&eventv1.Event{}).ProtoReflect().Descriptor()),
		Detections: describe((&detectionv1.Detection{}).ProtoReflect().Descriptor()),
	}
})

func describe(descriptor protoreflect.MessageDescriptor) map[Field]held {
	fields := make(map[Field]held)
	walk(descriptor, "", false, fields, 0)
	return fields
}

// A leaf reached through a repeated message is itself repeated, because the
// store keeps the list as one column per leaf: five parallel arrays are one
// table read sideways, and a question about `evidence.field` is a question about
// the column, not about a row of it.
func walk(descriptor protoreflect.MessageDescriptor, prefix string, inList bool, into map[Field]held, depth int) {
	if depth > maxDepth {
		return
	}

	fields := descriptor.Fields()
	for index := range fields.Len() {
		field := fields.Get(index)
		if field.IsMap() {
			continue
		}
		path := prefix + string(field.Name())
		repeated := inList || field.IsList()

		switch field.Kind() {
		case protoreflect.StringKind:
			into[Field(path)] = held{kind: Text, repeated: repeated}
		case protoreflect.BoolKind:
			into[Field(path)] = held{kind: Truth, repeated: repeated}
		case protoreflect.EnumKind:
			into[Field(path)] = held{kind: Choice, repeated: repeated, choices: choicesOf(field.Enum())}
		case protoreflect.MessageKind, protoreflect.GroupKind:
			name := string(field.Message().FullName())
			if name == timestamp {
				into[Field(path)] = held{kind: Instant, repeated: repeated}
				continue
			}
			if strings.HasPrefix(name, "google.protobuf.") {
				continue
			}
			walk(field.Message(), path+".", repeated, into, depth+1)
		default:
			if numeric(field.Kind()) {
				into[Field(path)] = held{kind: Number, repeated: repeated}
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

// A query names a choice the way a person would say it — `failure`, not
// `OUTCOME_FAILURE`. The zero value is left out: the store writes nothing where
// the contract says unspecified, so `not present` is the question that finds it
// and `equals unspecified` would be a second way to ask the same thing.
func choicesOf(enumeration protoreflect.EnumDescriptor) []string {
	prefix := upperSnake(string(enumeration.Name())) + "_"
	values := enumeration.Values()

	named := make([]string, 0, values.Len())
	for index := range values.Len() {
		short := strings.ToLower(strings.TrimPrefix(string(values.Get(index).Name()), prefix))
		if short == "unspecified" {
			continue
		}
		named = append(named, short)
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

func lookup(dataset Dataset, field Field) (held, bool) {
	known, declared := vocabularies()[dataset]
	if !declared {
		return held{}, false
	}
	entry, ok := known[field]
	return entry, ok
}

func KindOf(dataset Dataset, field Field) (Kind, bool) {
	entry, ok := lookup(dataset, field)
	return entry.kind, ok
}

// Whether the store keeps a list of this field rather than one value of it.
func Repeated(dataset Dataset, field Field) bool {
	entry, _ := lookup(dataset, field)
	return entry.repeated
}

// The values a choice field accepts, in the order the contract declares them.
func ChoicesOf(dataset Dataset, field Field) []string {
	entry, _ := lookup(dataset, field)
	return slices.Clone(entry.choices)
}

// Every field this dataset can be asked about, sorted, so a refusal can say what
// was available instead.
func Fields(dataset Dataset) []Field {
	known := vocabularies()[dataset]
	fields := make([]Field, 0, len(known))
	for field := range known {
		fields = append(fields, field)
	}
	slices.Sort(fields)
	return fields
}

func Known(dataset Dataset) bool {
	_, declared := vocabularies()[dataset]
	return declared
}
