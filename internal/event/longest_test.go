package event_test

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func texts(t *testing.T, descriptor protoreflect.MessageDescriptor, prefix string) []string {
	t.Helper()

	var paths []string
	fields := descriptor.Fields()
	for index := range fields.Len() {
		field := fields.Get(index)
		path := prefix + string(field.Name())
		switch {
		case field.IsList() || field.IsMap():
			t.Fatalf("%s is repeated, which this walk does not describe", path)
		case field.Kind() == protoreflect.StringKind:
			paths = append(paths, path)
		case field.Kind() == protoreflect.MessageKind && !strings.HasPrefix(string(field.Message().FullName()), "google.protobuf."):
			paths = append(paths, texts(t, field.Message(), path+".")...)
		}
	}
	return paths
}

func holding(t *testing.T, record *eventv1.Event, path, value string) {
	t.Helper()

	message := record.ProtoReflect()
	segments := strings.Split(path, ".")
	for index, segment := range segments {
		field := message.Descriptor().Fields().ByName(protoreflect.Name(segment))
		if field == nil {
			t.Fatalf("%s: the contract has no field %q on %s", path, segment, message.Descriptor().FullName())
		}
		if index == len(segments)-1 {
			message.Set(field, protoreflect.ValueOfString(value))
			return
		}
		message = message.Mutable(field).Message()
	}
}

func TestEveryTextTheContractCarriesHasALongest(t *testing.T) {
	for _, path := range texts(t, (&eventv1.Event{}).ProtoReflect().Descriptor(), "") {
		if _, bounded := event.LongestText(path); !bounded {
			t.Errorf("%s has no longest, and a detection quoting what it held would weigh whatever a producer sent", path)
		}
	}
}

func TestNoEventTheContractTakesHoldsMoreTextThanItsLongest(t *testing.T) {
	for _, path := range texts(t, (&eventv1.Event{}).ProtoReflect().Descriptor(), "") {
		t.Run(path, func(t *testing.T) {
			longest, _ := event.LongestText(path)
			record := valid()
			holding(t, record, path, strings.Repeat("a", longest+1))

			var violation *event.Violation
			if err := event.ValidateContract(record); !errors.As(err, &violation) || violation.Field != path {
				t.Fatalf("%d bytes were answered %v, and the contract says %s holds at most %d", longest+1, err, path, longest)
			}
		})
	}
}
