package analysis

import (
	"strings"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// Where an event goes once the engine knows what kind of thing it is. A route
// is the name the work is reported under, and the seam detection plugs into
// next; what it settles is that the decision is made in one place, from the
// contract, and that a class with no route is a visible outcome rather than a
// silent one.
type Route string

const RouteAuthentication Route = "authentication"

// What the engine does with one class of event: the route it is counted under,
// and the canonical form it is put into before anything reads it. Every stage
// a class grows is named here rather than branched on in the loop.
type Stage struct {
	Route     Route
	Normalize func(record *eventv1.Event) bool
}

// The whole routing table. A class the contract declares and this table does
// not name is refused by the suite, so a class added to the contract cannot
// arrive here unnoticed.
var routes = map[eventv1.EventClass]Stage{
	eventv1.EventClass_EVENT_CLASS_AUTHENTICATION: {
		Route:     RouteAuthentication,
		Normalize: normalizeAuthentication,
	},
}

func StageFor(class eventv1.EventClass) (Stage, bool) {
	stage, routed := routes[class]
	return stage, routed
}

func RouteFor(class eventv1.EventClass) (Route, bool) {
	stage, routed := StageFor(class)
	return stage.Route, routed
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
