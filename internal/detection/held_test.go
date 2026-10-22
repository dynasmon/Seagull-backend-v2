package detection_test

import (
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

const sourceAddress = detection.Field("authentication.network.source.ip")

func countingWithoutComparingTheSource() detection.Rule {
	subject := rule()
	subject.Match = detection.All{Terms: []detection.Expression{
		detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue("failure")},
		},
		detection.Predicate{
			Field:    "authentication.service.protocol",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue("ssh")},
		},
	}}
	subject.Count = detection.Count{
		AtLeast: 20,
		Within:  time.Minute,
		GroupBy: []detection.Field{sourceAddress, "origin.agent_id"},
	}
	return subject
}

func TestWhatADetectionHeldIsReadAsTheEventCarriedIt(t *testing.T) {
	made := detected(t, rule(), observed(t))

	for field, want := range map[detection.Field]string{
		sourceAddress:                     "203.0.113.10",
		"authentication.service.protocol": "ssh",
		"authentication.outcome":          "failure",
	} {
		held, carried := detection.HeldIn(made, field)
		if !carried || held != want {
			t.Errorf("%s reads as %q (carried %t), and the event held %q", field, held, carried, want)
		}
	}
}

func TestWhatACountingRuleGroupedByIsReadWhereItWasCounted(t *testing.T) {
	made := detected(t, countingWithoutComparingTheSource(), observed(t))
	for _, seen := range made.GetEvidence() {
		if detection.Field(seen.GetField()) == sourceAddress {
			t.Fatal("the counting rule compared the source it was meant only to group by")
		}
	}

	held, carried := detection.HeldIn(made, sourceAddress)
	if !carried || held != "203.0.113.10" {
		t.Errorf("the address the rule counted by reads as %q (carried %t)", held, carried)
	}
	if !detection.Speaks(made, sourceAddress) {
		t.Error("a detection grouped by the address is said to say nothing about it")
	}
}

func TestWhatAnOrderedRuleGroupedByIsReadWhereItWasOrdered(t *testing.T) {
	made := correlated(t, correlating(), observed(t))

	held, carried := detection.HeldIn(made, sourceAddress)
	if !carried || held != "203.0.113.10" {
		t.Errorf("the address the story is about reads as %q (carried %t)", held, carried)
	}
}

func TestAFieldTheEventDidNotCarryIsSpokenOfAndNotHeld(t *testing.T) {
	record := observed(t)
	record.GetAuthentication().GetNetwork().Source = nil
	made := detected(t, rule(), record)

	if held, carried := detection.HeldIn(made, sourceAddress); carried || held != "" {
		t.Errorf("an address the event did not carry reads as %q (carried %t)", held, carried)
	}
	if !detection.Speaks(made, sourceAddress) {
		t.Error("a detection whose rule asked about the address is said to say nothing about it")
	}
}

func TestAFieldTheRuleNeverReadIsNotSpokenOf(t *testing.T) {
	made := detected(t, rule(), observed(t))

	if held, carried := detection.HeldIn(made, "authentication.user.name"); carried || held != "" {
		t.Errorf("a field the rule never read reads as %q (carried %t)", held, carried)
	}
	if detection.Speaks(made, "authentication.user.name") {
		t.Error("a detection is said to speak of a field its rule never read")
	}
	if detection.Speaks(&detectionv1.Detection{}, sourceAddress) {
		t.Error("an empty detection is said to speak of a field")
	}
}
