package detection_test

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func TestTheVocabularyIsTheContract(t *testing.T) {
	held := map[detection.Field]detection.Kind{
		"event_id":                           detection.Text,
		"schema_version":                     detection.Number,
		"event_class":                        detection.Choice,
		"origin.agent_id":                    detection.Text,
		"origin.host.hostname":               detection.Text,
		"collection.sequence":                detection.Number,
		"authentication.user.name":           detection.Text,
		"authentication.network.source.port": detection.Number,
		"authentication.outcome":             detection.Choice,
		"authentication.network.transport":   detection.Choice,
	}
	for field, expected := range held {
		kind, declared := detection.KindOf(field)
		if !declared {
			t.Errorf("%s is not in the vocabulary and the contract declares it", field)
			continue
		}
		if kind != expected {
			t.Errorf("%s holds %s and the contract says %s", field, kind, expected)
		}
	}
}

// A timestamp is not something a stateless rule compares to a literal, so the
// walk stops at the contract's own messages and never descends into a
// well-known one.
func TestTimeIsNotAddressable(t *testing.T) {
	for _, field := range []detection.Field{"time", "time.event_time", "time.event_time.seconds", "reception.ingest_time"} {
		if _, declared := detection.KindOf(field); declared {
			t.Errorf("%s is offered to rules, and a window is not a predicate", field)
		}
	}
}

// A message is not a value either: a rule asks about a leaf.
func TestAFieldThatHoldsAMessageIsNotAddressable(t *testing.T) {
	for _, field := range []detection.Field{"origin", "origin.host", "authentication", "authentication.user"} {
		if _, declared := detection.KindOf(field); declared {
			t.Errorf("%s is offered to rules and holds a message rather than a value", field)
		}
	}
}

func TestAChoiceOffersTheValuesTheContractDeclares(t *testing.T) {
	choices := detection.ChoicesOf("authentication.outcome")
	if !slices.Equal(choices, []string{"unspecified", "success", "failure"}) {
		t.Errorf("authentication.outcome offers %v", choices)
	}
	if choices := detection.ChoicesOf("authentication.user.name"); len(choices) != 0 {
		t.Errorf("a text field offers choices: %v", choices)
	}
}

// The short name a rule writes — `failure` rather than `OUTCOME_FAILURE` — is
// the contract's value name with the enumeration's own name taken off it. That
// is a convention of the contract, so the suite holds it rather than trusting
// it: a value named differently would be offered to rules under a name that
// resolves to nothing.
func TestEveryEnumerationNamesItsValuesAfterItself(t *testing.T) {
	for _, enumeration := range enumerations(t) {
		prefix := upperSnake(string(enumeration.Name())) + "_"
		values := enumeration.Values()
		for index := range values.Len() {
			name := string(values.Get(index).Name())
			if !strings.HasPrefix(name, prefix) {
				t.Errorf("%s.%s does not start with %s, so a rule cannot name it in short form",
					enumeration.FullName(), name, prefix)
			}
		}
	}
}

// A body belongs to one class and a class carries one body, matched by name.
// The engine routes by class and a rule is registered on that route, so a body
// nobody can reach is a body no rule can ever match.
func TestEveryBodyBelongsToADeclaredClass(t *testing.T) {
	descriptor := (&eventv1.Event{}).ProtoReflect().Descriptor()

	bodies := make(map[string]struct{})
	oneofs := descriptor.Oneofs()
	for index := range oneofs.Len() {
		fields := oneofs.Get(index).Fields()
		for member := range fields.Len() {
			bodies[string(fields.Get(member).Name())] = struct{}{}
		}
	}

	classes := make(map[string]struct{})
	for value, name := range eventv1.EventClass_name {
		if eventv1.EventClass(value) == eventv1.EventClass_EVENT_CLASS_UNSPECIFIED {
			continue
		}
		classes[strings.ToLower(strings.TrimPrefix(name, "EVENT_CLASS_"))] = struct{}{}
	}

	for body := range bodies {
		if _, matched := classes[body]; !matched {
			t.Errorf("the body %q belongs to no class, so no rule can be routed to it", body)
		}
	}
	for class := range classes {
		if _, matched := bodies[class]; !matched {
			t.Errorf("the class %q carries no body, so a rule for it can only read the envelope", class)
		}
	}
}

func TestAFieldOfAnotherClassIsNotAddressable(t *testing.T) {
	authentication := eventv1.EventClass_EVENT_CLASS_AUTHENTICATION

	if !detection.AddressableBy("authentication.user.name", authentication) {
		t.Error("an authentication rule cannot reach its own body")
	}
	if !detection.AddressableBy("origin.host.hostname", authentication) {
		t.Error("a rule cannot reach the envelope every event carries")
	}
	if detection.AddressableBy("authentication.user.name", eventv1.EventClass(4242)) {
		t.Error("a class the contract does not declare reaches into a body that is not its own")
	}
	if detection.AddressableBy("authentication.user.nam", authentication) {
		t.Error("a field the contract does not declare is addressable")
	}
}

func enumerations(t *testing.T) []protoreflect.EnumDescriptor {
	t.Helper()

	var found []protoreflect.EnumDescriptor
	seen := make(map[protoreflect.FullName]struct{})

	var walk func(descriptor protoreflect.MessageDescriptor, depth int)
	walk = func(descriptor protoreflect.MessageDescriptor, depth int) {
		if depth > 8 {
			t.Fatalf("%s nests deeper than this walk goes", descriptor.FullName())
		}
		fields := descriptor.Fields()
		for index := range fields.Len() {
			field := fields.Get(index)
			switch field.Kind() {
			case protoreflect.EnumKind:
				if _, known := seen[field.Enum().FullName()]; !known {
					seen[field.Enum().FullName()] = struct{}{}
					found = append(found, field.Enum())
				}
			case protoreflect.MessageKind:
				if !strings.HasPrefix(string(field.Message().FullName()), "google.protobuf.") {
					walk(field.Message(), depth+1)
				}
			}
		}
	}
	walk((&eventv1.Event{}).ProtoReflect().Descriptor(), 0)

	if len(found) == 0 {
		t.Fatal("the contract declares no enumeration, so this rule guards nothing")
	}
	return found
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
