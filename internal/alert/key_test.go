package alert_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

func countedFrom(source string) *detectionv1.Detection {
	made := decided()
	made.Evidence = []*detectionv1.Evidence{
		{Field: "authentication.outcome", Operator: "equals", Held: "failure"},
		{Field: "authentication.service.protocol", Operator: "equals", Held: `"ssh"`},
	}
	made.Aggregation = &detectionv1.Aggregation{
		Count:     20,
		Threshold: 20,
		Group: []*detectionv1.Grouping{
			{Field: "authentication.network.source.ip", Value: source},
			{Field: "origin.agent_id", Value: "dev-agent-01"},
		},
	}
	return made
}

func TestAnEvidencePartNamingAFieldTheContractDoesNotDeclareIsRefused(t *testing.T) {
	for _, written := range []string{
		"evidence:authentication.source.ip",
		"evidence:authentication.network.source",
		"evidence:time.event_time",
		"evidence:",
	} {
		if part, err := alert.ParsePart(written); err == nil {
			t.Errorf("%s was read as the part %q", written, part)
		}
	}

	_, err := alert.ParsePart("evidence:authentication.source.ip")
	if !errors.Is(err, alert.ErrUndeclaredField) {
		t.Errorf("a field the contract does not declare was refused with %v", err)
	}

	part, err := alert.ParsePart(" evidence:authentication.network.source.ip ")
	if err != nil || part != bySourceAddress {
		t.Errorf("a field the contract declares was read as %q with %v", part, err)
	}
}

func TestATuningIsRefusedWhereverItNamesAFieldTheContractDoesNotDeclare(t *testing.T) {
	misspelt := alert.Part("evidence:authentication.source.ip")

	_, err := alert.NewTuning(keyed(alert.PartRule, misspelt), nil, nil)
	if !errors.Is(err, alert.ErrUndeclaredField) {
		t.Errorf("a default key naming an undeclared field compiled with %v", err)
	}

	_, err = alert.NewTuning(keyed(alert.PartRule), map[string]alert.Fold{"r": keyed(alert.PartRule, misspelt)}, nil)
	if !errors.Is(err, alert.ErrUndeclaredField) {
		t.Errorf("a per-rule key naming an undeclared field compiled with %v", err)
	}

	_, err = alert.NewTuning(keyed(alert.PartRule), nil, []alert.Suppression{{
		When:   alert.Selector{misspelt: {"203.0.113.10"}},
		Reason: "our own scanner",
	}})
	if !errors.Is(err, alert.ErrUndeclaredField) {
		t.Errorf("a suppression selecting on an undeclared field compiled with %v", err)
	}
}

func TestAKeyPartReadsTheAddressACountingRuleGroupedBy(t *testing.T) {
	bySource := []alert.Part{alert.PartRule, alert.PartAgent, bySourceAddress}

	one := alert.CorrelationKey(countedFrom("203.0.113.10"), bySource)
	again := alert.CorrelationKey(countedFrom("203.0.113.10"), bySource)
	other := alert.CorrelationKey(countedFrom("198.51.100.7"), bySource)

	if one != again {
		t.Error("two counts of one address did not share a key")
	}
	if one == other {
		t.Error("counts of two addresses shared a key that names the address")
	}
}

func TestASuppressionMatchesTextAsTheEventCarriedIt(t *testing.T) {
	made := decided()
	made.Evidence = []*detectionv1.Evidence{
		{Field: "authentication.network.source.ip", Operator: "starts_with", Negated: true, Held: `"203.0.113.10"`},
	}

	tuning := tuned(t, alert.Suppression{
		When:   alert.Selector{bySourceAddress: {"203.0.113.10"}},
		Reason: "our own scanner",
	})
	if _, hidden := tuning.Suppressed(made, instant(raisedAt)); !hidden {
		t.Error("a suppression naming the address the event carried did not hide the detection")
	}
	if _, hidden := tuning.Suppressed(countedFrom("203.0.113.10"), instant(raisedAt)); !hidden {
		t.Error("a suppression naming the address a count was grouped by did not hide the detection")
	}
}

func TestAKeyPartTheDetectionSaysNothingAboutIsReported(t *testing.T) {
	tuning, err := alert.NewTuning(keyed(alert.PartRule, alert.PartAgent, bySourceAddress), nil, nil)
	if err != nil {
		t.Fatalf("compile the tuning: %v", err)
	}

	silent := decided()
	silent.Evidence = []*detectionv1.Evidence{{Field: "authentication.outcome", Operator: "equals", Held: "failure"}}
	considered, err := alert.Consider(silent, tuning, instant(raisedAt))
	if err != nil {
		t.Fatalf("consider: %v", err)
	}
	if !slices.Equal(considered.Unspoken, []alert.Part{bySourceAddress}) {
		t.Errorf("a detection saying nothing of the address reported %v as unspoken", considered.Unspoken)
	}

	absent := decided()
	absent.Evidence = []*detectionv1.Evidence{{Field: "authentication.network.source.ip", Operator: "starts_with", Negated: true, Absent: true}}
	for name, made := range map[string]*detectionv1.Detection{
		"an address the event did not carry": absent,
		"an address a count was grouped by":  countedFrom("203.0.113.10"),
	} {
		considered, err := alert.Consider(made, tuning, instant(raisedAt))
		if err != nil {
			t.Fatalf("consider %s: %v", name, err)
		}
		if len(considered.Unspoken) != 0 {
			t.Errorf("%s reported %v as unspoken", name, considered.Unspoken)
		}
	}
}
