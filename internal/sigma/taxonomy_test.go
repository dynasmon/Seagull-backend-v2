package sigma

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const authentication = eventv1.EventClass_EVENT_CLASS_AUTHENTICATION

func TestEveryFieldTheTaxonomyNamesIsOneARuleCanReach(t *testing.T) {
	for name, held := range taxonomy {
		kind, declared := detection.KindOf(held.field)
		switch {
		case !declared:
			t.Errorf("%s stands for %q, which the contract does not declare", name, held.field)
			continue
		case !detection.AddressableBy(held.field, authentication):
			t.Errorf("%s stands for %q, which an authentication rule cannot reach", name, held.field)
		case held.holds == typed && kind == detection.Text:
			t.Errorf("%s stands for %q, which holds text, so how its case is compared is a decision this table has to make", name, held.field)
		case held.holds != typed && kind != detection.Text:
			t.Errorf("%s stands for %q, which holds %s, so case does not arise in it", name, held.field, kind)
		}
	}
}

// Sigma compares without case and the rule language compares with it, so what
// can be translated at all is what the canonical form already made comparable.
// This holds the table to that stage rather than to a claim about it: a field
// ADR 5 stops folding is a field this build must stop translating.
func TestTheCaseTheTaxonomyClaimsIsTheCaseTheCanonicalFormLeaves(t *testing.T) {
	stage, routed := analysis.StageFor(authentication)
	if !routed {
		t.Fatal("the contract declares a class the engine does not route")
	}

	for name, entry := range taxonomy {
		written, expected := "MiXeDCaSe", "mixedcase"
		switch entry.holds {
		case typed:
			continue
		case preserved:
			expected = written
		case canonical:
			written, expected = "::ffff:10.0.0.5", "10.0.0.5"
		}

		record := carrying(t, entry.field, written)
		stage.Normalize(record)

		if got := reads(t, record, entry.field); got != expected {
			t.Errorf("%s stands for %q, which the canonical form leaves as %q rather than %q", name, entry.field, got, expected)
		}
		if entry.holds == canonical && address(written) != expected {
			t.Errorf("%s translates %q into %q and the canonical form makes it %q", name, written, address(written), expected)
		}
	}
}

func carrying(t *testing.T, field detection.Field, value string) *eventv1.Event {
	t.Helper()

	record := &eventv1.Event{EventClass: authentication}
	message := record.ProtoReflect()

	steps := strings.Split(string(field), ".")
	for index, step := range steps {
		described := message.Descriptor().Fields().ByName(protoreflect.Name(step))
		if described == nil {
			t.Fatalf("the contract carries no %q on the way to %q", step, field)
		}
		if index == len(steps)-1 {
			message.Set(described, protoreflect.ValueOfString(value))
			break
		}
		message = message.Mutable(described).Message()
	}
	return record
}

func reads(t *testing.T, record *eventv1.Event, field detection.Field) string {
	t.Helper()

	message := record.ProtoReflect()
	steps := strings.Split(string(field), ".")
	for index, step := range steps {
		described := message.Descriptor().Fields().ByName(protoreflect.Name(step))
		if index == len(steps)-1 {
			return message.Get(described).String()
		}
		message = message.Mutable(described).Message()
	}
	return ""
}
