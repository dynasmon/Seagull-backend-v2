package analysis

import (
	"strings"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// Where an event goes once the engine knows what kind of thing it is. A route
// is a name today and the seam normalization and detection plug into
// tomorrow; what it settles now is that the decision is made in one place,
// from the contract, and that a class with no route is a visible outcome
// rather than a silent one.
type Route string

const RouteAuthentication Route = "authentication"

// The whole routing table. A class the contract declares and this table does
// not name is refused by the suite, so a class added to the contract cannot
// arrive here unnoticed.
var routes = map[eventv1.EventClass]Route{
	eventv1.EventClass_EVENT_CLASS_AUTHENTICATION: RouteAuthentication,
}

func RouteFor(class eventv1.EventClass) (Route, bool) {
	route, routed := routes[class]
	return route, routed
}

// Whether the contract this build carries has ever heard of the class. A
// producer cannot invent one that reaches here — the gateway validates a class
// before it admits the event — so a class this build does not declare means the
// stream is ahead of the process reading it.
func Declared(class eventv1.EventClass) bool {
	_, declared := eventv1.EventClass_name[int32(class)]
	return declared
}

// The contract's own name for a class, and "unknown" for a number it does not
// declare. The label is bounded by the enum on purpose: v1 had to collapse a
// metric label after a cardinality incident, and a class arriving from a newer
// producer must not be able to open one here.
func ClassName(class eventv1.EventClass) string {
	name, declared := eventv1.EventClass_name[int32(class)]
	if !declared {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(name, "EVENT_CLASS_"))
}
