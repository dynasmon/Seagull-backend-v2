package sigma

import (
	"fmt"
	"slices"
	"strings"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// What the canonical form did to a field before a rule ever reads it, which is
// what decides whether Sigma's case-insensitive comparison can be translated at
// all. ADR 5 draws the line and ADR 22 explains what follows from it: a field
// the canonical form folded can be compared without case because the event's
// own value was folded too, and a field it deliberately left alone cannot.
type comparison int

const (
	folded comparison = iota
	preserved
	canonical
	typed
)

type mapped struct {
	field detection.Field
	holds comparison
}

// The Sigma names this build understands and the contract fields they stand
// for. `TargetUserName`, `TargetDomainName`, `AuthenticationPackageName`,
// `ServiceName`, `Computer`, `SourceIp`, `SourcePort`, `DestinationIp`,
// `DestinationPort` and `Protocol` are Sigma's own; `Outcome`, `Activity` and
// `Transport` name what Seagull carries and Sigma's authentication taxonomy
// encodes in a Windows event identifier this platform does not receive.
var taxonomy = map[string]mapped{
	"Outcome":                   {"authentication.outcome", typed},
	"Activity":                  {"authentication.activity", typed},
	"AuthenticationPackageName": {"authentication.method", folded},
	"TargetUserName":            {"authentication.user.name", preserved},
	"TargetDomainName":          {"authentication.user.domain", folded},
	"ServiceName":               {"authentication.service.name", folded},
	"Protocol":                  {"authentication.service.protocol", folded},
	"SourceIp":                  {"authentication.network.source.ip", canonical},
	"SourcePort":                {"authentication.network.source.port", typed},
	"DestinationIp":             {"authentication.network.destination.ip", canonical},
	"DestinationPort":           {"authentication.network.destination.port", typed},
	"Transport":                 {"authentication.network.transport", typed},
	"Computer":                  {"origin.host.hostname", folded},
}

// A log source names the class of event the rule reads, so a Sigma rule written
// for telemetry this platform does not collect is refused before any of its
// fields are looked at.
var logsources = map[logsource]eventv1.EventClass{
	{Product: "linux", Service: "sshd"}: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
	{Product: "linux", Service: "auth"}: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
}

type logsource struct {
	Category string
	Product  string
	Service  string
}

func (l logsource) String() string {
	written := make([]string, 0, 3)
	for name, value := range map[string]string{"category": l.Category, "product": l.Product, "service": l.Service} {
		if value != "" {
			written = append(written, name+": "+value)
		}
	}
	slices.Sort(written)
	if len(written) == 0 {
		return "no category, product or service"
	}
	return strings.Join(written, ", ")
}

func Fields() []string {
	names := make([]string, 0, len(taxonomy))
	for name := range taxonomy {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func LogSources() []string {
	written := make([]string, 0, len(logsources))
	for source := range logsources {
		written = append(written, "{"+source.String()+"}")
	}
	slices.Sort(written)
	return written
}

func fieldsNamed() string { return strings.Join(Fields(), ", ") }

func classOf(source logsource) (eventv1.EventClass, error) {
	class, known := logsources[source]
	if !known {
		return class, fmt.Errorf("is %s, and this build translates a Sigma rule written for %s",
			source, strings.Join(LogSources(), " or "))
	}
	return class, nil
}
