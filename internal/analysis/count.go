package analysis

import (
	"context"
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	OutcomeCounted    = "counted"
	OutcomeReached    = "reached"
	OutcomeRepeated   = "repeated"
	OutcomeAtCapacity = "at_capacity"
	OutcomeTooLate    = "too_late"
	OutcomeUnbounded  = "unbounded"
	OutcomeRefused    = "refused"
)

// Whether a counting rule's window has reached what the rule asks for, and what
// it held when it did.
//
// Every window is event time and an event already folded moves nothing, so the
// same stream read twice reaches the same counts and decides the same
// detections: replay is how this state is built rather than a case it survives.
// Nothing is reset by firing — a rule at its threshold decides again on the next
// event that keeps it there, and folding those into one piece of work belongs to
// the alert plane, which is the only place that knows what work is. An event the
// window already holds decides nothing at all, so a batch redelivered without a
// restart cannot decide more than the delivery before it did.
func (e *Engine) reached(ctx context.Context, program *detection.Program, match *detection.Match, record *eventv1.Event) (bool, error) {
	rule := program.Rule()
	group := program.Group(record)
	key := detectionstate.KeyFor(record.GetOrigin().GetTenantId(), rule.ID, rule.Revision, group)

	held, err := e.state.Observe(ctx, key, detectionstate.Observation{
		Event: record.GetEventId(),
		At:    record.GetTime().GetEventTime().AsTime(),
	}, rule.Count.Within)
	if err != nil {
		if ctx.Err() != nil {
			return false, err
		}
		e.metrics.observed(refusalOf(err))
		return false, nil
	}
	if held.Repeated {
		e.metrics.observed(OutcomeRepeated)
		return false, nil
	}
	if held.Saturated {
		e.metrics.saturated()
	}

	if held.Count < rule.Count.AtLeast {
		e.metrics.observed(OutcomeCounted)
		return false, nil
	}
	e.metrics.observed(OutcomeReached)

	match.Counted = detection.Counted{
		Group:     group,
		Count:     held.Count,
		First:     held.First,
		Saturated: held.Saturated,
	}
	return true, nil
}

// A store that will not take an observation is counted and not logged: a flood
// of invented group values fills a store on every event it produces, and a line
// per event would be the flood written down a second time.
func refusalOf(err error) string {
	switch {
	case errors.Is(err, detectionstate.ErrAtCapacity):
		return OutcomeAtCapacity
	case errors.Is(err, detectionstate.ErrTooLate):
		return OutcomeTooLate
	case errors.Is(err, detectionstate.ErrWindowTooLong), errors.Is(err, detectionstate.ErrNoWindow):
		return OutcomeUnbounded
	}
	return OutcomeRefused
}

// How many keys the store the engine was given is holding, against what it was
// bounded to. Registered by the executable rather than by the store, because a
// domain package reports nothing, and rather than by the engine, because only
// the executable knows which store it chose.
func ObserveState(registry *metrics.Registry, bounds detectionstate.Bounds, keys func() int) {
	registry.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "detection",
			Name:      "state_keys",
			Help:      "Keys the detection state store is holding.",
		}, func() float64 { return float64(keys()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "detection",
			Name:      "state_key_ceiling",
			Help:      "Keys the detection state store was bounded to and refuses to go past.",
		}, func() float64 { return float64(bounds.Keys) }),
	)
}
