package broker

import (
	"testing"

	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

func TestAFindingAndTheAssessmentItWasDecidedInShareTheKeyOfTheirAgent(t *testing.T) {
	decided := &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Finding{Finding: &vulnerabilityv1.Finding{AgentId: "web-01", VulnerabilityId: "CVE-2024-6119"}}}
	assessed := &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Assessment{Assessment: &vulnerabilityv1.Assessment{AgentId: "web-01"}}}
	other := &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Finding{Finding: &vulnerabilityv1.Finding{AgentId: "db-01", VulnerabilityId: "CVE-2024-6119"}}}

	keys := map[string]string{}
	for name, record := range map[string]*vulnerabilityv1.FindingRecord{"finding": decided, "assessment": assessed, "other agent": other} {
		key, err := findingKey(record)
		if err != nil {
			t.Fatalf("the %s has no key: %v", name, err)
		}
		keys[name] = string(key)
	}
	if keys["finding"] != "web-01" || keys["assessment"] != keys["finding"] || keys["other agent"] != "db-01" {
		t.Fatalf("the records are keyed %v, and an asset's decisions and assessments have to share its agent's partition", keys)
	}

	for _, record := range []*vulnerabilityv1.FindingRecord{
		{},
		{Record: &vulnerabilityv1.FindingRecord_Finding{Finding: &vulnerabilityv1.Finding{}}},
		{Record: &vulnerabilityv1.FindingRecord_Assessment{Assessment: &vulnerabilityv1.Assessment{}}},
	} {
		if key, err := findingKey(record); err == nil {
			t.Errorf("%v was keyed %q", record, key)
		}
	}
}
