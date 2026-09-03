package incident_test

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

var (
	failed   = time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)
	accepted = time.Date(2026, 9, 3, 11, 0, 40, 0, time.UTC)
	raisedAt = time.Date(2026, 9, 3, 11, 1, 0, 0, time.UTC)
)

func correlated(spread time.Duration) *detectionv1.Detection {
	return &detectionv1.Detection{
		DetectionId: "bc84b318fe13e6f6ad86d64da0730a07",
		Rule: &detectionv1.Rule{
			Id: "ssh.password_guessing_that_succeeded", Revision: 1,
			Name: "SSH password guessing that succeeded",
		},
		RulesetId:  "89ab5f2c",
		Severity:   detectionv1.Severity_SEVERITY_CRITICAL,
		Technique:  &detectionv1.Technique{Tactic: "credential_access", Id: "T1110.001", Name: "Password Guessing"},
		EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Origin:     &eventv1.Origin{TenantId: "acme", AgentId: "dev-agent-01"},
		EventTime:  timestamppb.New(accepted),
		Correlation: &detectionv1.Correlation{
			Stages: []*detectionv1.Stage{
				{Name: "a failed password", EventId: "event-1", EventTime: timestamppb.New(failed)},
				{Name: "one that was accepted", EventId: "event-2", EventTime: timestamppb.New(accepted)},
			},
			Window:      durationpb.New(5 * time.Minute),
			ClockSpread: durationpb.New(spread),
			Group: []*detectionv1.Grouping{
				{Field: "authentication.network.source.ip", Value: "203.0.113.10"},
				{Field: "origin.agent_id", Value: "dev-agent-01"},
			},
		},
	}
}

func TestAnIncidentIsNamedByTheCorrelationItIsAbout(t *testing.T) {
	made := correlated(0)

	opened, err := incident.Raise(made, raisedAt)
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	if opened.GetIncidentId() != made.GetDetectionId() {
		t.Errorf("the incident is named %q and the detection %q", opened.GetIncidentId(), made.GetDetectionId())
	}
	if opened.GetDetectionId() != made.GetDetectionId() {
		t.Error("the incident does not name the detection it was told by")
	}

	again, err := incident.Raise(made, raisedAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("raise the same story again: %v", err)
	}
	if again.GetIncidentId() != opened.GetIncidentId() {
		t.Error("the same correlation opened two incidents")
	}
}

func TestTheStoryCarriesOneEventPerStageAndTheSpanTheyCover(t *testing.T) {
	opened, err := incident.Raise(correlated(0), raisedAt)
	if err != nil {
		t.Fatalf("raise: %v", err)
	}

	if len(opened.GetStages()) != 2 {
		t.Fatalf("the incident carries %d stages", len(opened.GetStages()))
	}
	if opened.GetStages()[0].GetEventId() != "event-1" || opened.GetStages()[1].GetEventId() != "event-2" {
		t.Error("the stages do not name the events the correlation named")
	}
	if !opened.GetFirstEventTime().AsTime().Equal(failed) {
		t.Errorf("the story began at %s", opened.GetFirstEventTime().AsTime())
	}
	if !opened.GetLastEventTime().AsTime().Equal(accepted) {
		t.Errorf("the story ended at %s", opened.GetLastEventTime().AsTime())
	}
	if len(opened.GetGroup()) != 2 || opened.GetGroup()[0].GetValue() != "203.0.113.10" {
		t.Error("the incident does not say what the story is about")
	}
}

func TestARaisedIncidentStartsOpenAtTheBeginningOfItsTrail(t *testing.T) {
	opened, err := incident.Raise(correlated(0), raisedAt)
	if err != nil {
		t.Fatalf("raise: %v", err)
	}

	if state, _ := incident.FromWire(opened.GetState()); state != incident.Open {
		t.Errorf("a raised incident is %s", state)
	}
	if opened.GetRevision() != 1 || opened.GetChangedBy() != incident.Platform {
		t.Errorf("a raised incident is at revision %d, changed by %q", opened.GetRevision(), opened.GetChangedBy())
	}
	if opened.GetAssignee() != "" || opened.GetClosure() != nil {
		t.Error("a raised incident is already held or closed")
	}

	line := incident.Raised(opened)
	if line.GetFrom() != 0 || line.GetTo() != opened.GetState() || line.GetRevision() != 1 {
		t.Error("the first line of the trail does not say the incident was opened")
	}
	if line.GetActor() != incident.Platform {
		t.Errorf("the incident was opened by %q", line.GetActor())
	}
}

func TestTheAnalyticalHalfIsCopiedAndNotShared(t *testing.T) {
	made := correlated(0)

	opened, err := incident.Raise(made, raisedAt)
	if err != nil {
		t.Fatalf("raise: %v", err)
	}

	made.Rule.Name = "renamed after the incident was raised"
	made.Correlation.Stages[0].EventId = "another-event"
	made.Correlation.Group[0].Value = "198.51.100.7"

	if opened.GetRule().GetName() == made.GetRule().GetName() {
		t.Error("the incident shares the rule with the detection it was made from")
	}
	if opened.GetStages()[0].GetEventId() != "event-1" {
		t.Error("the incident shares its stages with the detection it was made from")
	}
	if opened.GetGroup()[0].GetValue() != "203.0.113.10" {
		t.Error("the incident shares its grouping with the detection it was made from")
	}
}

func TestADetectionThatTellsNoStoryNeverBecomesAnIncident(t *testing.T) {
	single := correlated(0)
	single.Correlation = nil
	if incident.Correlates(single) {
		t.Error("a detection with no correlation reports itself a story")
	}
	if _, err := incident.Raise(single, raisedAt); !errors.Is(err, incident.ErrNoStory) {
		t.Errorf("a detection with no correlation was raised as %v", err)
	}

	untenanted := correlated(0)
	untenanted.Origin = &eventv1.Origin{AgentId: "dev-agent-01"}
	if _, err := incident.Raise(untenanted, raisedAt); !errors.Is(err, incident.ErrNoTenant) {
		t.Errorf("a story nobody can be scoped to was raised as %v", err)
	}

	unnamed := correlated(0)
	unnamed.DetectionId = ""
	if _, err := incident.Raise(unnamed, raisedAt); !errors.Is(err, incident.ErrUnnamed) {
		t.Errorf("an unnamed story was raised as %v", err)
	}
}
