package analysis

import (
	"iter"
	"log/slog"
	"slices"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The rules an event is decided against. Holding a ruleset and running one are
// separate capabilities, so an executable is what puts the two together — the
// same seam, and the same reason, as the backbone source the engine consumes.
type Rules interface {
	Current() Ruleset
}

// One immutable set of compiled rules, named by what is in it. It is taken once
// per event and held for the whole of deciding that event, so a ruleset
// replaced in the middle changes what the next event is read against and never
// what this one is being read against.
type Ruleset interface {
	ID() string
	For(class eventv1.EventClass) iter.Seq[*detection.Program]
}

// Decide one event against every rule registered on the route its class sends
// it down.
//
// Nothing here writes anything. A detection is a record that crosses a runtime
// boundary and it needs a contract of its own before it can leave the process;
// until that exists a match is counted and reported, which is enough to say a
// rule fires and deliberately not enough to act on.
func (e *Engine) detect(record *eventv1.Event, route Route, position Record) {
	rules := e.rules.Current()
	if rules == nil {
		return
	}

	started := time.Now()
	evaluated := 0
	for program := range rules.For(record.GetEventClass()) {
		evaluated++
		if match, held := program.Decide(record); held {
			e.detected(match, rules.ID(), record, route, position)
		}
	}
	e.metrics.evaluated(route, evaluated, time.Since(started))
}

// A match is reported by what decided it and what it decided about, never by
// what the event held: a field value can carry attacker input, and evidence
// belongs in the detection record rather than in a log line. The fields the rule
// read are named instead, because those come from the contract and say why the
// rule fired without quoting anything a producer wrote.
func (e *Engine) detected(match detection.Match, ruleset string, record *eventv1.Event, route Route, position Record) {
	e.metrics.detected(route, match.Rule.Severity)
	e.logger.Info("detection",
		slog.String("rule", string(match.Rule.ID)),
		slog.Int("revision", match.Rule.Revision),
		slog.String("severity", string(match.Rule.Severity)),
		slog.String("ruleset", ruleset),
		slog.String("event", record.GetEventId()),
		slog.String("tenant", record.GetOrigin().GetTenantId()),
		slog.String("agent", record.GetOrigin().GetAgentId()),
		slog.Any("fields", evidenced(match.Evidence)),
		slog.Int("partition", int(position.Partition)),
		slog.Int64("offset", position.Offset),
	)
}

// The fields the rule read, each named once: a rule may ask three questions
// about one field, and which they were is a property of the rule rather than of
// the event that answered them.
func evidenced(evidence []detection.Evidence) []string {
	fields := make([]string, 0, len(evidence))
	for _, seen := range evidence {
		if !slices.Contains(fields, string(seen.Field)) {
			fields = append(fields, string(seen.Field))
		}
	}
	return fields
}
