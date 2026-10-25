package analysis_test

import (
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func failedOn(t *testing.T, agent, id string, after time.Duration) analysis.Record {
	t.Helper()
	return staged(t, timed{at: began.Add(after), outcome: eventv1.Outcome_OUTCOME_FAILURE, agent: agent, id: id})
}

func acceptedOn(t *testing.T, agent, id string, after time.Duration) analysis.Record {
	t.Helper()
	return staged(t, timed{at: began.Add(after), outcome: eventv1.Outcome_OUTCOME_SUCCESS, agent: agent, id: id})
}

func TestADetectionOfOneAgentsEventsKeepsTheNameItCarriedBeforeStagesNamedTheirAgents(t *testing.T) {
	for _, one := range []struct {
		kind    string
		program *detection.Program
		records []analysis.Record
		named   string
	}{
		{
			"single event", compiled(t, "ssh.failed_password", "failure"),
			[]analysis.Record{failedOn(t, "web-01", "web-01-000000001", 0)},
			"11abba04ffd1954bc9200508a28c7b94",
		},
		{
			"count", threshold(t, 2, 10*time.Minute, "authentication.network.source.ip", "origin.agent_id"),
			[]analysis.Record{failedOn(t, "web-01", "web-01-000000001", 0), failedOn(t, "web-01", "web-01-000000002", time.Second)},
			"1ff9410b8395b714884edf9ca321ca55",
		},
		{
			"story", story(t, 5*time.Minute, "authentication.network.source.ip", "origin.agent_id"),
			[]analysis.Record{failedOn(t, "web-01", "web-01-000000001", 0), acceptedOn(t, "web-01", "web-01-000000002", 30*time.Second)},
			"cde3c0d403c710646e5d248ae9143a29",
		},
	} {
		t.Run(one.kind, func(t *testing.T) {
			made := process(t, one.program, one.records)
			if len(made) != 1 || made[0].GetDetectionId() != one.named {
				t.Fatalf("one agent's %s is named %v and was named %s before stages named their agents",
					one.kind, names(made), one.named)
			}
		})
	}
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

func TestAnotherAgentsEventUnderAToldStagesIdentifierDoesNotTellTheStoryAgain(t *testing.T) {
	made := process(t, story(t, 5*time.Minute, "authentication.network.source.ip"), []analysis.Record{
		failedOn(t, "web-01", "shared-000000001", 0),
		acceptedOn(t, "web-02", "web-02-000000001", 30*time.Second),
		failedOn(t, "web-03", "shared-000000001", 10*time.Second),
	})
	if len(made) != 1 {
		t.Fatalf("a story told once, then a failure another agent sent under its first stage's identifier, made %d detections", len(made))
	}
}

func TestAStoryTwoAgentsToldUnderOneIdentifierIsADetectionItsConsumersTake(t *testing.T) {
	made := process(t, story(t, 5*time.Minute, "authentication.network.source.ip"), []analysis.Record{
		failedOn(t, "web-01", "shared-000000001", 0),
		acceptedOn(t, "web-02", "shared-000000001", 30*time.Second),
	})
	if len(made) != 1 {
		t.Fatalf("two agents sharing an event identifier told the story %d times", len(made))
	}

	if err := detection.ValidateContract(made[0]); err != nil {
		t.Fatalf("the consumers of a story two agents told under one identifier refuse it: %v", err)
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

	if inOrder[0].GetDetectionId() != reversed[0].GetDetectionId() {
		t.Fatalf("one story was named %s in order and %s reversed",
			inOrder[0].GetDetectionId(), reversed[0].GetDetectionId())
	}
}
