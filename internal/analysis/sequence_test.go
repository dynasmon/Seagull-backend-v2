package analysis_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func story(t *testing.T, within time.Duration, group ...detection.Field) *detection.Program {
	t.Helper()

	outcome := func(held string) detection.Expression {
		return detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue(held)},
		}
	}
	program, err := detection.Compile(detection.Rule{
		ID:          "ssh.password_guessing_that_succeeded",
		Revision:    1,
		Name:        "SSH password guessing that succeeded",
		Description: "A failed password from an address, then one that was accepted from the same address.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Sequence: detection.Sequence{
			Within:  within,
			GroupBy: group,
			Stages: []detection.Stage{
				{Name: "a failed password", Match: outcome("failure")},
				{Name: "one that was accepted", Match: outcome("success")},
			},
		},
		Severity: detection.Critical,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("compile a sequence rule: %v", err)
	}
	return program
}

type timed struct {
	at       time.Time
	outcome  eventv1.Outcome
	source   string
	observed time.Duration
}

func staged(t *testing.T, seen timed) analysis.Record {
	t.Helper()

	if seen.source == "" {
		seen.source = "203.0.113.10"
	}
	record := fixtures.SSHAuthentication{
		EventID:  fmt.Sprintf("%s-%s-%d", seen.source, seen.outcome, seen.at.UnixNano()),
		SourceIP: seen.source,
		Outcome:  seen.outcome,
		At:       seen.at,
	}.Event()

	// The gateway writes the reception and a producer cannot, so moving the
	// observed time against it is how a test says what the platform saw of the
	// clock that timed the event.
	record.Time.ObservedTime = timestamppb.New(seen.at.Add(seen.observed))
	record.Reception = &eventv1.Reception{IngestTime: timestamppb.New(seen.at), Gateway: "ingest-01"}

	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return analysis.Record{Partition: 0, Offset: seen.at.UnixNano(), Value: payload}
}

func failed(t *testing.T, after time.Duration) analysis.Record {
	return staged(t, timed{at: began.Add(after), outcome: eventv1.Outcome_OUTCOME_FAILURE})
}

func accepted(t *testing.T, after time.Duration) analysis.Record {
	return staged(t, timed{at: began.Add(after), outcome: eventv1.Outcome_OUTCOME_SUCCESS})
}

func TestASequenceIsDecidedOnTheEventThatCompletesIt(t *testing.T) {
	made, _ := held(t, bounded(), story(t, 5*time.Minute), []analysis.Record{
		failed(t, 0),
		failed(t, 10*time.Second),
		accepted(t, 20*time.Second),
	})

	if len(made) != 1 {
		t.Fatalf("three events told the story %d times", len(made))
	}
	told := made[0].GetCorrelation()
	if len(told.GetStages()) != 2 {
		t.Fatalf("the story reports %d stages", len(told.GetStages()))
	}
	if name := told.GetStages()[0].GetName(); name != "a failed password" {
		t.Errorf("the first stage reads %q", name)
	}
	if events := made[0].GetSourceEventIds(); len(events) != 2 {
		t.Errorf("the detection names %d events and the story is made of two", len(events))
	}
	if at := made[0].GetEventTime().AsTime(); !at.Equal(began.Add(20 * time.Second)) {
		t.Errorf("the detection is placed at %s rather than where the story ended", at)
	}
	if window := told.GetWindow().AsDuration(); window != 5*time.Minute {
		t.Errorf("the story carries a window of %s", window)
	}
}

func TestASequenceIsToldOncePerWindowThatHoldsIt(t *testing.T) {
	made, _ := held(t, bounded(), story(t, time.Minute), []analysis.Record{
		failed(t, 0),
		accepted(t, 10*time.Second),
		accepted(t, 20*time.Second),
		accepted(t, 30*time.Second),
	})
	if len(made) != 1 {
		t.Fatalf("three successes after one failure told the story %d times", len(made))
	}

	again, _ := held(t, bounded(), story(t, time.Minute), []analysis.Record{
		failed(t, 0),
		accepted(t, 10*time.Second),
		failed(t, 5*time.Minute),
		accepted(t, 5*time.Minute+10*time.Second),
	})
	if len(again) != 2 {
		t.Fatalf("two stories a window apart were told %d times", len(again))
	}
	if again[0].GetDetectionId() == again[1].GetDetectionId() {
		t.Error("two stories a window apart share a name")
	}
}

// The card's own requirement: the order of the story is its event times, and
// the order it was delivered in is not part of it.
func TestASequenceDoesNotDependOnPerfectArrivalOrder(t *testing.T) {
	forwards, _ := held(t, bounded(), story(t, 5*time.Minute), []analysis.Record{
		failed(t, 0),
		accepted(t, 30*time.Second),
	})
	backwards, _ := held(t, bounded(), story(t, 5*time.Minute), []analysis.Record{
		accepted(t, 30*time.Second),
		failed(t, 0),
	})

	if len(forwards) != 1 || len(backwards) != 1 {
		t.Fatalf("the story was told %d times in order and %d times out of order", len(forwards), len(backwards))
	}
	if forwards[0].GetDetectionId() != backwards[0].GetDetectionId() {
		t.Error("the same two events out of order told a different story")
	}
	if !proto.Equal(forwards[0].GetCorrelation(), backwards[0].GetCorrelation()) {
		t.Error("the same two events out of order were written down differently")
	}
}

// The late-arrival policy, in the two halves ADR 18 left it in: inside the
// window an event lands where it happened, and outside it the observation is
// refused rather than folded into a window reaching further back than the rule
// asked for.
func TestALateEventIsFoldedWhereItHappenedOrRefused(t *testing.T) {
	made, registry := held(t, bounded(), story(t, time.Minute), []analysis.Record{
		accepted(t, 2*time.Minute),
		failed(t, 90*time.Second),
	})
	if len(made) != 1 {
		t.Fatalf("a failure arriving after the success it preceded told the story %d times", len(made))
	}

	missed, refusals := held(t, bounded(), story(t, time.Minute), []analysis.Record{
		accepted(t, 2*time.Minute),
		failed(t, 0),
	})
	if len(missed) != 0 {
		t.Errorf("a failure two minutes outside a one-minute window told %d stories", len(missed))
	}
	if body := exposition(t, refusals); !strings.Contains(body, analysis.OutcomeTooLate) {
		t.Error("an observation older than its window was refused and not counted")
	}
	_ = registry
}

// Clock skew is not ignored silently: the order rests on the producer's clock,
// and how far that stood from the platform's own is measured, carried and
// counted rather than assumed away.
func TestClockSkewIsMeasuredAndReported(t *testing.T) {
	agreed, _ := held(t, bounded(), story(t, 5*time.Minute), []analysis.Record{
		staged(t, timed{at: began, outcome: eventv1.Outcome_OUTCOME_FAILURE}),
		staged(t, timed{at: began.Add(30 * time.Second), outcome: eventv1.Outcome_OUTCOME_SUCCESS}),
	})
	if len(agreed) != 1 {
		t.Fatalf("the story was told %d times", len(agreed))
	}
	if spread := agreed[0].GetCorrelation().GetClockSpread().AsDuration(); spread != 0 {
		t.Errorf("one clock spread by %s", spread)
	}

	disagreed, registry := held(t, bounded(), story(t, 5*time.Minute), []analysis.Record{
		staged(t, timed{at: began, outcome: eventv1.Outcome_OUTCOME_FAILURE}),
		staged(t, timed{at: began.Add(30 * time.Second), outcome: eventv1.Outcome_OUTCOME_SUCCESS, observed: 2 * time.Minute}),
	})
	if len(disagreed) != 1 {
		t.Fatalf("the story was told %d times", len(disagreed))
	}
	if spread := disagreed[0].GetCorrelation().GetClockSpread().AsDuration(); spread != 2*time.Minute {
		t.Errorf("clocks two minutes apart were reported as %s", spread)
	}
	if body := exposition(t, registry); !strings.Contains(body, "seagull_detection_sequences_unordered_total 1") {
		t.Error("a story its clocks cannot order was not counted")
	}
}

func TestReplayingASequenceNamesTheSameStory(t *testing.T) {
	records := []analysis.Record{failed(t, 0), failed(t, time.Second), accepted(t, 2*time.Second)}

	first, _ := held(t, bounded(), story(t, 5*time.Minute), records)
	again, _ := held(t, bounded(), story(t, 5*time.Minute), records)
	if len(first) != 1 || len(again) != 1 {
		t.Fatalf("the stream told %d stories and the replay told %d", len(first), len(again))
	}
	if first[0].GetDetectionId() != again[0].GetDetectionId() {
		t.Error("a replay named the same story differently")
	}
	if !proto.Equal(first[0].GetCorrelation(), again[0].GetCorrelation()) {
		t.Error("a replay wrote the same story down differently")
	}

	twice, _ := held(t, bounded(), story(t, 5*time.Minute), append(append([]analysis.Record{}, records...), records...))
	if len(twice) != 1 {
		t.Errorf("a batch delivered twice without a restart told the story %d times", len(twice))
	}
}

func TestASequenceIsToldWithinItsGroup(t *testing.T) {
	made, _ := held(t, bounded(), story(t, 5*time.Minute, "authentication.network.source.ip"), []analysis.Record{
		staged(t, timed{at: began, outcome: eventv1.Outcome_OUTCOME_FAILURE, source: "203.0.113.10"}),
		staged(t, timed{at: began.Add(time.Second), outcome: eventv1.Outcome_OUTCOME_SUCCESS, source: "198.51.100.7"}),
	})
	if len(made) != 0 {
		t.Fatalf("two addresses told one story %d times", len(made))
	}

	shared, _ := held(t, bounded(), story(t, 5*time.Minute, "authentication.network.source.ip"), []analysis.Record{
		staged(t, timed{at: began, outcome: eventv1.Outcome_OUTCOME_FAILURE, source: "203.0.113.10"}),
		staged(t, timed{at: began.Add(time.Second), outcome: eventv1.Outcome_OUTCOME_SUCCESS, source: "203.0.113.10"}),
	})
	if len(shared) != 1 {
		t.Fatalf("one address told its own story %d times", len(shared))
	}
	if group := shared[0].GetCorrelation().GetGroup(); len(group) != 1 || group[0].GetValue() != "203.0.113.10" {
		t.Errorf("the story is grouped by %v", group)
	}
}

func TestTemporalStateStaysBounded(t *testing.T) {
	bounds := detectionstate.Bounds{Window: time.Hour, ObservationsPerKey: 1, Keys: 4}
	if err := bounds.Orders(story(t, time.Minute).Rule().Sequence); err == nil {
		t.Error("a store holding one observation per key admitted a story of two stages")
	}

	flood := make([]analysis.Record, 0, 16)
	for index := range 16 {
		flood = append(flood, staged(t, timed{
			at:      began.Add(time.Duration(index) * time.Second),
			outcome: eventv1.Outcome_OUTCOME_FAILURE,
			source:  fmt.Sprintf("198.51.100.%d", index),
		}))
	}

	narrow := detectionstate.Bounds{Window: time.Hour, ObservationsPerKey: 8, Keys: 4}
	_, registry := held(t, narrow, story(t, time.Minute, "authentication.network.source.ip"), flood)
	if body := exposition(t, registry); !strings.Contains(body, analysis.OutcomeAtCapacity) {
		t.Error("a flood of invented group values was not refused at the key ceiling")
	}
}

func TestAnEventNoStageAnswersIsNotRemembered(t *testing.T) {
	program, err := detection.Compile(detection.Rule{
		ID:          "ssh.password_guessing_against_one_account",
		Revision:    1,
		Name:        "SSH password guessing against one account",
		Description: "A failure and then a success against an account the rule names.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Sequence: detection.Sequence{
			Within: 5 * time.Minute,
			Stages: []detection.Stage{
				{Name: "a failed password", Match: detection.Predicate{
					Field: "authentication.user.name", Operator: detection.Equals, Values: []detection.Value{detection.TextValue("root")},
				}},
				{Name: "one that was accepted", Match: detection.Predicate{
					Field: "authentication.user.name", Operator: detection.Equals, Values: []detection.Value{detection.TextValue("postgres")},
				}},
			},
		},
		Severity: detection.High,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("compile a sequence rule: %v", err)
	}

	record := fixtures.SSHAuthentication{EventID: "nobody-at-all", Username: "nobody", At: began}.Event()
	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}

	made, registry := held(t, bounded(), program, []analysis.Record{{Value: payload}})
	if len(made) != 0 {
		t.Errorf("an event answering no stage told %d stories", len(made))
	}
	if body := exposition(t, registry); strings.Contains(body, "state_observations_total") {
		t.Error("an event answering no stage was folded into the window")
	}
}
