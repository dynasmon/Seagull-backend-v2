package analysis_test

import (
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The rule that keeps the routing table and the contract from drifting apart:
// a class the contract declares is a class the engine has decided about, and
// the only class that may have no route is the one that says nothing.
func TestEveryClassTheContractDeclaresHasARoute(t *testing.T) {
	for value, name := range eventv1.EventClass_name {
		class := eventv1.EventClass(value)
		_, routed := analysis.RouteFor(class)

		if class == eventv1.EventClass_EVENT_CLASS_UNSPECIFIED {
			if routed {
				t.Errorf("%s has a route: an event that does not say what it is cannot be analysed", name)
			}
			continue
		}
		if !routed {
			t.Errorf("%s has no route: name it in internal/analysis so the engine decides rather than drops", name)
		}
	}
}

func TestAnAuthenticationEventIsRoutedToAuthentication(t *testing.T) {
	route, routed := analysis.RouteFor(eventv1.EventClass_EVENT_CLASS_AUTHENTICATION)
	if !routed {
		t.Fatal("the class the contract declares has no route")
	}
	if route != analysis.RouteAuthentication {
		t.Errorf("authentication routes to %q", route)
	}
}

// The version-skew case: a producer running a newer contract publishes a class
// this build has never heard of.
func TestAClassOutsideTheContractIsNotDeclaredAndNotRouted(t *testing.T) {
	ahead := eventv1.EventClass(4242)

	if analysis.Declared(ahead) {
		t.Error("a class the contract does not carry is reported as declared")
	}
	if _, routed := analysis.RouteFor(ahead); routed {
		t.Error("a class the contract does not carry was given a route")
	}
	if name := analysis.ClassName(ahead); name != "unknown" {
		t.Errorf("an undeclared class is labelled %q, which is unbounded", name)
	}
}

func TestAClassIsLabelledByTheContractsNameForIt(t *testing.T) {
	labels := map[eventv1.EventClass]string{
		eventv1.EventClass_EVENT_CLASS_UNSPECIFIED:    "unspecified",
		eventv1.EventClass_EVENT_CLASS_AUTHENTICATION: "authentication",
	}
	for class, expected := range labels {
		if name := analysis.ClassName(class); name != expected {
			t.Errorf("%v is labelled %q and should be %q", class, name, expected)
		}
	}
}
