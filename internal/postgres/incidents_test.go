package postgres

import (
	"testing"
	"time"
)

func TestAStageComesBackWithTheAgentThatSentItsEvent(t *testing.T) {
	at := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

	told := restoreStages([]string{"a failed password", "one that was accepted"}, []string{"e1", "e2"},
		[]time.Time{at, at.Add(time.Minute)}, []string{"web-01", "web-02"})
	if len(told) != 2 || told[0].GetAgentId() != "web-01" || told[1].GetAgentId() != "web-02" {
		t.Errorf("a story web-01 and web-02 told came back as %v", told)
	}
}

func TestAStoryStoredBeforeStagesNamedTheirAgentsComesBackWithItsStages(t *testing.T) {
	at := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

	told := restoreStages([]string{"a failed password", "one that was accepted"}, []string{"e1", "e2"},
		[]time.Time{at, at.Add(time.Minute)}, []string{})
	if len(told) != 2 {
		t.Fatalf("a story stored without its stages' agents came back with %d stages", len(told))
	}
	for _, stage := range told {
		if stage.GetAgentId() != "" {
			t.Errorf("a stage stored without its agent came back from %s", stage.GetAgentId())
		}
	}
}
