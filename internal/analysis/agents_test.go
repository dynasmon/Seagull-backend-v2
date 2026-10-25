package analysis_test

import (
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// A test that reproduces the defect of an open card. It is skipped while the
// defect is there and fails as soon as it is gone, so the marker leaves with the
// fix and the assertions after it become the regression test.
func stillOpen(t *testing.T, card string, reproduced bool, defect string) {
	t.Helper()

	if reproduced {
		t.Skipf("%s is open: %s", card, defect)
	}
	t.Fatalf("%s no longer reproduces: remove this marker so the test guards the fix", card)
}

func failedOn(t *testing.T, agent, id string, after time.Duration) analysis.Record {
	t.Helper()
	return staged(t, timed{at: began.Add(after), outcome: eventv1.Outcome_OUTCOME_FAILURE, agent: agent, id: id})
}

func acceptedOn(t *testing.T, agent, id string, after time.Duration) analysis.Record {
	t.Helper()
	return staged(t, timed{at: began.Add(after), outcome: eventv1.Outcome_OUTCOME_SUCCESS, agent: agent, id: id})
}

func TestTwoAgentsSendingOneEventIdentifierAreCountedApart(t *testing.T) {
	program := threshold(t, 2, 10*time.Minute, "authentication.network.source.ip")

	if made := process(t, program, []analysis.Record{
		failedOn(t, "web-01", "web-01-000000001", 0),
		failedOn(t, "web-02", "web-02-000000001", time.Second),
	}); len(made) != 1 {
		t.Fatalf("two failures from two agents against a threshold of two made %d detections", len(made))
	}

	made := process(t, program, []analysis.Record{
		failedOn(t, "web-01", "shared-000000001", 0),
		failedOn(t, "web-02", "shared-000000001", time.Second),
	})
	if len(made) != 1 {
		t.Fatalf("two agents sharing an event identifier made %d detections against a threshold of two", len(made))
	}
}

func TestTwoAgentsSendingOneEventIdentifierStillTellAStory(t *testing.T) {
	program := story(t, 5*time.Minute, "authentication.network.source.ip")

	if made := process(t, program, []analysis.Record{
		failedOn(t, "web-01", "web-01-000000001", 0),
		acceptedOn(t, "web-02", "web-02-000000001", 30*time.Second),
	}); len(made) != 1 {
		t.Fatalf("a failure on one agent and a success on another told the story %d times", len(made))
	}

	made := process(t, program, []analysis.Record{
		failedOn(t, "web-01", "shared-000000001", 0),
		acceptedOn(t, "web-02", "shared-000000001", 30*time.Second),
	})
	if len(made) != 1 {
		t.Fatalf("two agents sharing an event identifier told the story %d times", len(made))
	}
}

func TestAStoryAcrossAgentsIsNamedTheSameWhicheverEventArrivesLast(t *testing.T) {
	program := story(t, 5*time.Minute, "authentication.network.source.ip")
	failedOnOne := failedOn(t, "web-01", "web-01-000000001", 0)
	acceptedOnAnother := acceptedOn(t, "web-02", "web-02-000000001", 30*time.Second)

	inOrder := process(t, program, []analysis.Record{failedOnOne, acceptedOnAnother})
	reversed := process(t, program, []analysis.Record{acceptedOnAnother, failedOnOne})
	if len(inOrder) != 1 || len(reversed) != 1 {
		t.Fatalf("a story across two agents was found %d times in order and %d times reversed",
			len(inOrder), len(reversed))
	}

	renamed := inOrder[0].GetDetectionId() != reversed[0].GetDetectionId()
	stillOpen(t, "BE-093", renamed,
		"a detection is named after the agent of the event that completed it, so the arrival order renames a story")
	if renamed {
		t.Fatalf("one story was named %s in order and %s reversed",
			inOrder[0].GetDetectionId(), reversed[0].GetDetectionId())
	}
}
