package detection_test

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventcontract "github.com/dynasmon/Seagull-backend-v2/internal/event"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

func refusedAt(t *testing.T, made *detectionv1.Detection) string {
	t.Helper()

	err := detection.ValidateContract(made)
	var violation *eventcontract.Violation
	if !errors.As(err, &violation) {
		t.Fatalf("the detection was answered with %v rather than a refusal of one of its fields", err)
	}
	return violation.Field
}

func TestAStageNamesAnAgentACertificateCouldHaveCarried(t *testing.T) {
	made := toldBy(t, completedOn(t, "web-01"), stagesFrom(t, "web-01", "web-02"))
	made.Correlation.Stages[0].AgentId = "web 01"

	if field := refusedAt(t, made); field != "correlation.stages[0].agent_id" {
		t.Errorf("a stage naming an agent no certificate carries was refused at %s", field)
	}
}

func TestEveryStageNamesItsAgentOrNoneDoes(t *testing.T) {
	made := toldBy(t, completedOn(t, "web-01"), stagesFrom(t, "web-01", "web-02"))

	partial := proto.Clone(made).(*detectionv1.Detection)
	partial.Correlation.Stages[0].AgentId = ""
	if field := refusedAt(t, partial); field != "correlation.stages" {
		t.Errorf("a story naming the agent of one stage and not the other was refused at %s", field)
	}

	before := proto.Clone(made).(*detectionv1.Detection)
	for _, stage := range before.Correlation.Stages {
		stage.AgentId = ""
	}
	if err := detection.ValidateContract(before); err != nil {
		t.Errorf("a story decided before stages named their agents was refused: %v", err)
	}
}

func TestTwoAgentsMayShareAnEventIdentifierAndOneAgentMayNotNameItTwice(t *testing.T) {
	stages := stagesFrom(t, "web-01", "web-02")
	stages[1].Event = stages[0].Event

	shared := toldBy(t, completedOn(t, "web-01"), stages)
	if err := detection.ValidateContract(shared); err != nil {
		t.Errorf("a story two agents told under one identifier was refused: %v", err)
	}

	repeated := proto.Clone(shared).(*detectionv1.Detection)
	repeated.Correlation.Stages[1].AgentId = "web-01"
	repeated.Origin.AgentId = "web-01"
	if field := refusedAt(t, repeated); field != "correlation.stages[1].event_id" {
		t.Errorf("a story naming one agent's event twice was refused at %s", field)
	}

	before := proto.Clone(shared).(*detectionv1.Detection)
	for _, stage := range before.Correlation.Stages {
		stage.AgentId = ""
	}
	if field := refusedAt(t, before); field != "correlation.stages[1].event_id" {
		t.Errorf("a story naming an identifier twice and no agent was refused at %s", field)
	}
}

func TestAStoryIsAboutTheAgentOfItsLastStage(t *testing.T) {
	made := toldBy(t, completedOn(t, "web-01"), stagesFrom(t, "web-01", "web-02"))
	made.Origin.AgentId = "web-01"

	if field := refusedAt(t, made); field != "origin.agent_id" {
		t.Errorf("a story ending on web-02 and said to be about web-01 was refused at %s", field)
	}
}
