package analysis_test

import (
	"slices"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
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

func failedForOn(t *testing.T, user, agent, id string, after time.Duration) analysis.Record {
	t.Helper()
	return staged(t, timed{at: began.Add(after), outcome: eventv1.Outcome_OUTCOME_FAILURE, agent: agent, id: id, user: user})
}

func sprayed(t *testing.T) *detection.Program {
	t.Helper()

	outcome := func(held string) detection.Expression {
		return detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue(held)},
		}
	}
	failedFor := func(user string) detection.Expression {
		return detection.All{Terms: []detection.Expression{
			outcome("failure"),
			detection.Predicate{
				Field:    "authentication.user.name",
				Operator: detection.Equals,
				Values:   []detection.Value{detection.TextValue(user)},
			},
		}}
	}
	program, err := detection.Compile(detection.Rule{
		ID:          "ssh.passwords_sprayed_across_hosts_then_accepted",
		Revision:    1,
		Name:        "SSH passwords sprayed across hosts, then one accepted",
		Description: "A failed password for root, one for admin and an accepted one, from one address across the estate.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Sequence: detection.Sequence{
			Within:  5 * time.Minute,
			GroupBy: []detection.Field{"authentication.network.source.ip"},
			Stages: []detection.Stage{
				{Name: "a failed password for root", Match: failedFor("root")},
				{Name: "a failed password for admin", Match: failedFor("admin")},
				{Name: "one that was accepted", Match: outcome("success")},
			},
		},
		Severity: detection.Critical,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("compile a sequence rule across agents: %v", err)
	}
	return program
}

// Every order the backbone may deliver the partitions in: each partition's own
// records stay in the order it holds them, and the partitions interleave freely.
func interleavings(partitions ...[]analysis.Record) [][]analysis.Record {
	var orders [][]analysis.Record
	var walk func(delivered []analysis.Record, left [][]analysis.Record)
	walk = func(delivered []analysis.Record, left [][]analysis.Record) {
		finished := true
		for index, partition := range left {
			if len(partition) == 0 {
				continue
			}
			finished = false
			rest := slices.Clone(left)
			rest[index] = partition[1:]
			walk(append(slices.Clone(delivered), partition[0]), rest)
		}
		if finished {
			orders = append(orders, delivered)
		}
	}
	walk(nil, partitions)
	return orders
}

func stageAgents(made *detectionv1.Detection) []string {
	agents := make([]string, 0, len(made.GetCorrelation().GetStages()))
	for _, stage := range made.GetCorrelation().GetStages() {
		agents = append(agents, stage.GetAgentId())
	}
	return agents
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

func TestAStoryAcrossAgentsIsOneDetectionUnderOneNameInEveryOrderItsPartitionsInterleave(t *testing.T) {
	program := sprayed(t)
	orders := interleavings(
		[]analysis.Record{
			failedForOn(t, "root", "web-01", "web-01-000000001", 0),
			acceptedOn(t, "web-01", "web-01-000000002", 30*time.Second),
		},
		[]analysis.Record{failedForOn(t, "admin", "web-02", "web-02-000000001", 10*time.Second)},
		[]analysis.Record{failedForOn(t, "nobody", "web-03", "web-03-000000001", 20*time.Second)},
	)
	if len(orders) != 12 {
		t.Fatalf("three partitions holding two, one and one records interleave %d ways", len(orders))
	}

	var named string
	for _, order := range orders {
		made := process(t, program, order)
		if len(made) != 1 {
			t.Fatalf("one story across agents was told %d times in one order", len(made))
		}
		if named == "" {
			named = made[0].GetDetectionId()
		}
		if made[0].GetDetectionId() != named {
			t.Fatalf("one story across agents was named %s and %s in two orders", named, made[0].GetDetectionId())
		}
		if agents := stageAgents(made[0]); !slices.Equal(agents, []string{"web-01", "web-02", "web-01"}) {
			t.Errorf("the stages name the agents %v", agents)
		}
		if origin := made[0].GetOrigin(); origin.GetAgentId() != "web-01" || origin.GetTenantId() != "default" || origin.GetHost() != nil {
			t.Errorf("a story across agents ending on web-01 is about %v", origin)
		}
		if err := detection.ValidateContract(made[0]); err != nil {
			t.Errorf("the consumers of a story across agents refuse it: %v", err)
		}
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
