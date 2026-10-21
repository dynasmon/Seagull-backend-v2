package alert_test

import (
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
