package incident

import (
	"strings"
	"time"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

// How far the platform vouches for the order the story rests on, measured and
// never declared: a rule author states how much a story would matter, and
// cannot state how well the clocks of an estate agree.
//
// The yardstick is the one the rule already chose. Clocks that spread less than
// the story lasted order it themselves, which is the same test the detection
// reports as its ordering; clocks that spread further than that but less than
// the window still place the events inside what the rule was looking at, so they
// belong together and their order does not follow; wider than the window, and
// nothing in the data supports either.
func Confidence(correlation *detectionv1.Correlation) incidentv1.Confidence {
	if len(correlation.GetStages()) == 0 {
		return incidentv1.Confidence_CONFIDENCE_UNSPECIFIED
	}

	spread := correlation.GetClockSpread().AsDuration()
	switch {
	case spread < Span(correlation):
		return incidentv1.Confidence_CONFIDENCE_HIGH
	case spread < correlation.GetWindow().AsDuration():
		return incidentv1.Confidence_CONFIDENCE_MEDIUM
	default:
		return incidentv1.Confidence_CONFIDENCE_LOW
	}
}

// How long the story lasted, in the event time the stages were ordered by.
func Span(correlation *detectionv1.Correlation) time.Duration {
	stages := correlation.GetStages()
	if len(stages) < 2 {
		return 0
	}
	first, last := stages[0].GetEventTime(), stages[len(stages)-1].GetEventTime()
	if first == nil || last == nil {
		return 0
	}
	return last.AsTime().Sub(first.AsTime())
}

func Level(value incidentv1.Confidence) string {
	trimmed := strings.TrimPrefix(value.String(), "CONFIDENCE_")
	if trimmed == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(trimmed)
}
