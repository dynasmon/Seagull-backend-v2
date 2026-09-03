package incident_test

import (
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

func TestConfidenceIsTheClockSpreadReadAgainstTheStoryAndTheWindow(t *testing.T) {
	span := accepted.Sub(failed)

	for _, one := range []struct {
		spread time.Duration
		want   incidentv1.Confidence
		why    string
	}{
		{0, incidentv1.Confidence_CONFIDENCE_HIGH, "clocks that agreed order the story themselves"},
		{span - time.Second, incidentv1.Confidence_CONFIDENCE_HIGH, "a spread inside the span still orders it"},
		{span, incidentv1.Confidence_CONFIDENCE_MEDIUM, "a spread as wide as the span does not order it"},
		{4 * time.Minute, incidentv1.Confidence_CONFIDENCE_MEDIUM, "the events are still inside the window"},
		{5 * time.Minute, incidentv1.Confidence_CONFIDENCE_LOW, "the spread reaches the whole window"},
		{time.Hour, incidentv1.Confidence_CONFIDENCE_LOW, "the clocks say nothing about either"},
	} {
		got := incident.Confidence(correlated(one.spread).GetCorrelation())
		if got != one.want {
			t.Errorf("a spread of %s is %s and should be %s: %s",
				one.spread, incident.Level(got), incident.Level(one.want), one.why)
		}
	}
}

func TestAStoryWithNoStagesHasNoConfidenceToReport(t *testing.T) {
	if got := incident.Confidence(nil); got != incidentv1.Confidence_CONFIDENCE_UNSPECIFIED {
		t.Errorf("a missing correlation is %s", incident.Level(got))
	}
	if incident.Level(incidentv1.Confidence_CONFIDENCE_UNSPECIFIED) != "" {
		t.Error("an unspecified confidence is written as something")
	}
}

func TestTheSpanIsMeasuredAcrossTheStagesInEventTime(t *testing.T) {
	told := correlated(0).GetCorrelation()
	if got := incident.Span(told); got != accepted.Sub(failed) {
		t.Errorf("the story spans %s", got)
	}

	told.Stages = told.GetStages()[:1]
	if got := incident.Span(told); got != 0 {
		t.Errorf("one stage spans %s", got)
	}
}

func TestEveryConfidenceIsWrittenTheWayTheStoreKeepsIt(t *testing.T) {
	written := map[string]bool{}
	for value := incidentv1.Confidence_CONFIDENCE_LOW; value <= incidentv1.Confidence_CONFIDENCE_HIGH; value++ {
		level := incident.Level(value)
		if level == "" {
			t.Errorf("%s is written as nothing", value)
		}
		if written[level] {
			t.Errorf("%s shares a written form with another level", value)
		}
		written[level] = true
	}
	if len(written) != 3 {
		t.Fatalf("the platform reports %d levels of confidence", len(written))
	}
}
