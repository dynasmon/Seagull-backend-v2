package detection_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func authentication(t *testing.T, outcome string) *eventv1.Event {
	t.Helper()

	held := eventv1.Outcome_OUTCOME_FAILURE
	if outcome == "success" {
		held = eventv1.Outcome_OUTCOME_SUCCESS
	}
	return fixtures.SSHAuthentication{Outcome: held}.Event()
}

func ordering() detection.Rule {
	subject := rule()
	subject.Match = nil
	subject.Sequence = detection.Sequence{
		Within:  5 * time.Minute,
		GroupBy: []detection.Field{"authentication.network.source.ip"},
		Stages: []detection.Stage{
			{Name: "a failed password", Match: detection.Predicate{
				Field: "authentication.outcome", Operator: detection.Equals, Values: []detection.Value{detection.TextValue("failure")},
			}},
			{Name: "one that was accepted", Match: detection.Predicate{
				Field: "authentication.outcome", Operator: detection.Equals, Values: []detection.Value{detection.TextValue("success")},
			}},
		},
	}
	return subject
}

func TestASequenceIsRefusedWhereItWasWritten(t *testing.T) {
	for _, refused := range []struct {
		name    string
		part    string
		written func(*detection.Rule)
	}{
		{"a sequence beside a match", "sequence", func(r *detection.Rule) {
			r.Match = detection.Predicate{Field: "authentication.outcome", Operator: detection.Present}
		}},
		{"a sequence beside a count", "sequence", func(r *detection.Rule) {
			r.Count = detection.Count{AtLeast: 20, Within: time.Minute}
		}},
		{"a story of one stage", "sequence.stages", func(r *detection.Rule) {
			r.Sequence.Stages = r.Sequence.Stages[:1]
		}},
		{"more stages than a rule may order", "sequence.stages", func(r *detection.Rule) {
			for range detection.MaxStages {
				r.Sequence.Stages = append(r.Sequence.Stages, r.Sequence.Stages[0])
			}
		}},
		{"a sequence with no window", "sequence.within", func(r *detection.Rule) { r.Sequence.Within = 0 }},
		{"a window longer than a rule may remember", "sequence.within", func(r *detection.Rule) {
			r.Sequence.Within = detection.MaxWithin + time.Second
		}},
		{"a stage with no name", "sequence.stages[1].name", func(r *detection.Rule) { r.Sequence.Stages[1].Name = "" }},
		{"two stages under one name", "sequence.stages[1].name", func(r *detection.Rule) {
			r.Sequence.Stages[1].Name = r.Sequence.Stages[0].Name
		}},
		{"a stage that asks nothing", "sequence.stages[1].match", func(r *detection.Rule) { r.Sequence.Stages[1].Match = nil }},
		{"grouping by the tenant", "sequence.group_by[0]", func(r *detection.Rule) {
			r.Sequence.GroupBy = []detection.Field{"origin.tenant_id"}
		}},
		{"grouping by the event itself", "sequence.group_by[0]", func(r *detection.Rule) {
			r.Sequence.GroupBy = []detection.Field{"event_id"}
		}},
	} {
		t.Run(refused.name, func(t *testing.T) {
			subject := ordering()
			refused.written(&subject)

			err := subject.Validate()
			var violation *detection.Violation
			if !errors.As(err, &violation) {
				t.Fatalf("the rule was accepted, or refused as %v", err)
			}
			if violation.Part != refused.part {
				t.Errorf("the refusal names %q and should name %q: %s", violation.Part, refused.part, violation.Reason)
			}
		})
	}
}

// A rule that orders is a rule with stages and nothing else changes: the same
// class routes it, the same fields address it, and the same compiler resolves
// every stage against the contract.
func TestASequenceCompilesEveryStageAgainstTheContract(t *testing.T) {
	program, err := detection.Compile(ordering())
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	if !program.Correlates() || program.Counts() {
		t.Error("a rule with a sequence should correlate and not count")
	}
	if stages := program.Stages(); len(stages) != 2 || stages[0] != "a failed password" {
		t.Errorf("the stages read back as %v", stages)
	}
	if written := program.String(); !strings.Contains(written, "then") {
		t.Errorf("the compiled sequence writes back as %s", written)
	}

	broken := ordering()
	broken.Sequence.Stages[1].Match = detection.Predicate{
		Field: "authentication.nothing_of_the_sort", Operator: detection.Present,
	}
	if _, err := detection.Compile(broken); err == nil {
		t.Error("a stage naming a field the contract does not declare compiled")
	}
}

// Which stages an event satisfies is asked of the event alone, and an event that
// satisfies none is not part of any story the rule is telling.
func TestAnEventSatisfiesTheStagesItAnswers(t *testing.T) {
	program, err := detection.Compile(ordering())
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	failure := authentication(t, "failure")
	reached, evidence := program.Satisfied(failure)
	switch {
	case !reached.Has(0):
		t.Error("a failed password did not satisfy the stage written for it")
	case reached.Has(1):
		t.Error("a failed password satisfied the stage written for a success")
	case len(evidence) == 0:
		t.Error("a satisfied stage gathered no evidence")
	}

	if reached, _ := program.Satisfied(authentication(t, "success")); !reached.Has(1) || reached.Has(0) {
		t.Error("a successful login satisfied the wrong stages")
	}
}

// An event a rule admits at two steps is usable at either. Choosing here would
// make a sequence depend on which stage its author happened to write first.
func TestAnEventCanSatisfyMoreThanOneStage(t *testing.T) {
	subject := ordering()
	subject.Sequence.Stages[1].Match = detection.Predicate{Field: "authentication.outcome", Operator: detection.Present}

	program, err := detection.Compile(subject)
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	reached, _ := program.Satisfied(authentication(t, "failure"))
	if !reached.Has(0) || !reached.Has(1) {
		t.Errorf("an event answering both stages satisfied %v", reached)
	}
	if carried := detection.StagesOf(reached.String()); carried != reached {
		t.Errorf("a stage set written down as %q read back as %v", reached.String(), carried)
	}
}

// The order rests on the producer's clock, so a story whose events were timed by
// clocks further apart than the story lasted is one the data does not order.
func TestASequenceSaysWhenItsOrderIsNotEstablished(t *testing.T) {
	at := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	told := func(spread time.Duration) detection.Correlated {
		return detection.Correlated{ClockSpread: spread, Stages: []detection.Satisfied{
			{Name: "a failed password", Event: "one", At: at},
			{Name: "one that was accepted", Event: "two", At: at.Add(30 * time.Second)},
		}}
	}

	if span := told(0).Span(); span != 30*time.Second {
		t.Errorf("the story spans %s", span)
	}
	if !told(time.Second).Ordered() {
		t.Error("clocks a second apart do not unorder a story half a minute long")
	}
	if told(time.Minute).Ordered() {
		t.Error("clocks a minute apart cannot order a story half a minute long")
	}
	if events := told(0).Events(); len(events) != 2 || events[0] != "one" {
		t.Errorf("the story names %v", events)
	}
}
