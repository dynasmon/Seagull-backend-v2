package analysis

import (
	"context"
	"iter"
	"log/slog"
	"slices"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
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

// Where a detection goes once it has been made. Nothing in this process acts on
// one: it is put on the backbone and whatever materialises it is a consumer of
// its own, which is what keeps the shape of an alert table out of the thing that
// decides what an alert is about.
//
// Stated here and chosen by the executable, as the backbone source is.
type Detections interface {
	Publish(ctx context.Context, made []*detectionv1.Detection) error
}

// Decide one event against every rule registered on the route its class sends
// it down, and say what was found.
//
// Nothing is published here. The batch is what becomes durable, and it becomes
// durable before the group position advances, so what leaves this function is
// held until the whole batch has been decided.
func (e *Engine) detect(record *eventv1.Event, route Route, position Record, at time.Time) []*detectionv1.Detection {
	rules := e.rules.Current()
	if rules == nil {
		return nil
	}

	var made []*detectionv1.Detection
	started := time.Now()
	evaluated := 0
	for program := range rules.For(record.GetEventClass()) {
		evaluated++
		if match, held := program.Decide(record); held {
			made = append(made, e.detected(match, rules.ID(), record, route, position, at))
		}
	}
	e.metrics.evaluated(route, evaluated, time.Since(started))
	return made
}

// A match is reported by what decided it and what it decided about, never by
// what the event held: a field value can carry attacker input, and evidence
// belongs in the detection record rather than in a log line. The fields the rule
// read are named instead, because those come from the contract and say why the
// rule fired without quoting anything a producer wrote.
//
// The detection is named in the log line so that an operator reading one can
// find the record carrying the evidence, and the record can be found without
// reading the log.
func (e *Engine) detected(match detection.Match, ruleset string, record *eventv1.Event, route Route, position Record, at time.Time) *detectionv1.Detection {
	made := match.Detected(ruleset, record, at)

	e.metrics.detected(route, match.Rule.Severity)
	e.logger.Info("detection",
		slog.String("detection", made.GetDetectionId()),
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
	return made
}

// Retried until the backbone has them or the process is stopping; nothing is
// dropped to make progress. The group position advances only after this returns,
// so a backbone that will not take a detection becomes visible consumer lag
// rather than a finding nobody was told about.
//
// A batch published twice says the same thing twice: every detection in it is
// named by the rule and the events it was decided from and by nothing else, so
// whatever materialises it rewrites what it already holds instead of adding a
// second copy of it. That is what makes retrying safe here.
func (e *Engine) publish(ctx context.Context, made []*detectionv1.Detection) error {
	if len(made) == 0 {
		return nil
	}

	delay := e.retryDelay
	for attempt := 1; ; attempt++ {
		err := e.emit(ctx, made)
		if err == nil {
			e.metrics.published(len(made))
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		e.metrics.publishRetried()
		e.logger.Error("detections_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("detections", len(made)),
			slog.Duration("retry_in", delay),
			slog.String("error", err.Error()),
		)

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
		delay = min(delay*2, e.maxRetryDelay)
	}
}

func (e *Engine) emit(ctx context.Context, made []*detectionv1.Detection) error {
	publishCtx, cancel := context.WithTimeout(ctx, e.publishTimeout)
	defer cancel()
	return e.detections.Publish(publishCtx, made)
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
