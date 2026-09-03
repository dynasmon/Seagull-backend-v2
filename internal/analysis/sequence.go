package analysis

import (
	"context"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	OutcomeStaged    = "staged"
	OutcomeCompleted = "completed"
)

// Whether this event completed the story the rule is written for, and which
// events told it.
//
// The order is read out of the window rather than out of the arrival of the
// events, so a stage satisfied by an event that arrives after a later stage
// still lands where it happened and still completes the sequence. What decides
// is the fold that made the window completable, whichever stage its event
// satisfied: a sequence is therefore found the same number of times however the
// backbone happened to deliver it, and only which of several interchangeable
// earlier events it cites can differ.
func (e *Engine) completed(ctx context.Context, program *detection.Program, match *detection.Match, record *eventv1.Event) (bool, error) {
	reached, evidence := program.Satisfied(record)
	if !reached.Any() {
		return false, nil
	}

	rule := program.Rule()
	group := program.Group(record)
	key := detectionstate.KeyFor(record.GetOrigin().GetTenantId(), rule.ID, rule.Revision, group)

	held, window, err := e.state.Ordered(ctx, key, detectionstate.Observation{
		Event: record.GetEventId(),
		At:    record.GetTime().GetEventTime().AsTime(),
		Value: reached.String(),
		Skew:  skewOf(record),
	}, rule.Sequence.Within)
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

	stages := program.Stages()
	told, complete := ordered(window, len(stages), "")
	if !complete {
		e.metrics.observed(OutcomeStaged)
		return false, nil
	}
	if _, before := ordered(window, len(stages), record.GetEventId()); before {
		e.metrics.observed(OutcomeStaged)
		return false, nil
	}
	e.metrics.observed(OutcomeCompleted)

	match.Evidence = evidence
	match.Correlated = correlated(stages, told, group)
	if !match.Correlated.Ordered() {
		e.metrics.unordered()
	}
	return true, nil
}

// The earliest assignment of the window to the stages, in event time. Earliest
// finds one whenever one exists: a later choice at any stage leaves no more of
// the window for the stages after it than the earliest does.
func ordered(window []detectionstate.Observation, stages int, without string) ([]detectionstate.Observation, bool) {
	told := make([]detectionstate.Observation, 0, stages)
	for _, seen := range window {
		if len(told) == stages {
			break
		}
		if seen.Event == without || !detection.StagesOf(seen.Value).Has(len(told)) {
			continue
		}
		told = append(told, seen)
	}
	return told, len(told) == stages
}

func correlated(stages []string, told []detectionstate.Observation, group []detection.Binding) detection.Correlated {
	found := detection.Correlated{Group: group, Stages: make([]detection.Satisfied, 0, len(stages))}

	widest, narrowest := told[0].Skew, told[0].Skew
	for index, seen := range told {
		found.Stages = append(found.Stages, detection.Satisfied{Name: stages[index], Event: seen.Event, At: seen.At})
		widest = max(widest, seen.Skew)
		narrowest = min(narrowest, seen.Skew)
	}
	found.ClockSpread = widest - narrowest
	return found
}

// What the platform saw of the clock that timed this event: the producer said
// when its collector read the record, and the gateway wrote when it admitted
// the batch. Events from one agent share a clock and spread by transit alone;
// events from two spread by whatever their clocks disagree about, which is what
// bounds how wrong an ordering built out of them can be.
func skewOf(record *eventv1.Event) time.Duration {
	observed, admitted := record.GetTime().GetObservedTime(), record.GetReception().GetIngestTime()
	if observed == nil || admitted == nil {
		return 0
	}
	return observed.AsTime().Sub(admitted.AsTime())
}
