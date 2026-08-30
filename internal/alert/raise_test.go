package alert_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const raisedAt = "2026-08-30T12:00:00Z"

func decided() *detectionv1.Detection {
	happened := timestamppb.New(instant("2026-08-30T11:59:00Z"))
	return &detectionv1.Detection{
		DetectionId: "bc84b318fe13e6f6ad86d64da0730a07",
		Rule: &detectionv1.Rule{
			Id:       "ssh_password_failure_from_outside",
			Revision: 1,
			Name:     "SSH password failure from outside",
			Source:   &detectionv1.Source{Catalogue: "sigma", Identifier: "5013fd8a"},
		},
		RulesetId:  "3538ec98f5ce3e22e8e65f47cd0344ee",
		Severity:   detectionv1.Severity_SEVERITY_MEDIUM,
		Technique:  &detectionv1.Technique{Tactic: "credential_access", Id: "T1110.001", Name: "Password Guessing"},
		EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Origin:     &eventv1.Origin{TenantId: "acme", AgentId: "dev-agent-01"},
		EventTime:  happened,
	}
}

func instant(written string) time.Time {
	parsed, err := time.Parse(time.RFC3339, written)
	if err != nil {
		panic(err)
	}
	return parsed
}

func TestAnAlertIsNamedByTheDetectionItIsAbout(t *testing.T) {
	made := decided()

	raised, err := alert.Raise(made, instant(raisedAt))
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	if raised.GetAlertId() != made.GetDetectionId() {
		t.Errorf("the alert is called %q and the detection %q", raised.GetAlertId(), made.GetDetectionId())
	}

	again, err := alert.Raise(made, instant("2026-08-30T18:00:00Z"))
	if err != nil {
		t.Fatalf("raise again: %v", err)
	}
	if again.GetAlertId() != raised.GetAlertId() {
		t.Error("the same detection raised two differently named alerts")
	}
}

func TestARaisedAlertStartsOpenAtTheBeginningOfItsTrail(t *testing.T) {
	raised, err := alert.Raise(decided(), instant(raisedAt))
	if err != nil {
		t.Fatalf("raise: %v", err)
	}

	if raised.GetState() != alertv1.State_STATE_OPEN {
		t.Errorf("a raised alert is %s", raised.GetState())
	}
	if raised.GetRevision() != 1 {
		t.Errorf("a raised alert is at revision %d", raised.GetRevision())
	}
	if raised.GetAssignee() != "" {
		t.Errorf("a raised alert is already assigned to %q", raised.GetAssignee())
	}
	if raised.GetClosure() != nil {
		t.Error("a raised alert carries a closure")
	}
	if raised.GetChangedBy() != alert.Platform {
		t.Errorf("a raised alert was changed by %q", raised.GetChangedBy())
	}
	if !raised.GetRaisedAt().AsTime().Equal(instant(raisedAt)) {
		t.Errorf("a raised alert was raised at %s", raised.GetRaisedAt().AsTime())
	}

	first := alert.Raised(raised)
	if first.GetFrom() != alertv1.State_STATE_UNSPECIFIED || first.GetTo() != alertv1.State_STATE_OPEN {
		t.Errorf("the first line of the trail runs %s -> %s", first.GetFrom(), first.GetTo())
	}
	if first.GetActor() != alert.Platform || first.GetRevision() != 1 {
		t.Errorf("the first line is %q at revision %d", first.GetActor(), first.GetRevision())
	}
}

func TestTheAnalyticalHalfIsCopiedAndNotShared(t *testing.T) {
	made := decided()

	raised, err := alert.Raise(made, instant(raisedAt))
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	if raised.GetRule() == made.GetRule() {
		t.Fatal("the alert points at the detection's rule instead of copying it")
	}
	if raised.GetTechnique() == made.GetTechnique() {
		t.Fatal("the alert points at the detection's technique instead of copying it")
	}

	made.Rule.Name = "renamed after the alert was raised"
	if raised.GetRule().GetName() == made.GetRule().GetName() {
		t.Error("changing the detection changed the alert")
	}

	if raised.GetTenantId() != made.GetOrigin().GetTenantId() {
		t.Errorf("the alert's tenant is %q and the detection's is %q", raised.GetTenantId(), made.GetOrigin().GetTenantId())
	}
	if raised.GetAgentId() != made.GetOrigin().GetAgentId() {
		t.Errorf("the alert is about agent %q", raised.GetAgentId())
	}
	if raised.GetSeverity() != made.GetSeverity() || raised.GetEventClass() != made.GetEventClass() {
		t.Error("the alert disagrees with the detection about severity or class")
	}
}

func TestADetectionThatCannotBeScopedNeverBecomesAnAlert(t *testing.T) {
	unnamed := decided()
	unnamed.DetectionId = ""
	if _, err := alert.Raise(unnamed, instant(raisedAt)); !errors.Is(err, alert.ErrUnnamed) {
		t.Errorf("an unnamed detection raised %v", err)
	}

	untenanted := decided()
	untenanted.Origin = &eventv1.Origin{AgentId: "dev-agent-01"}
	if _, err := alert.Raise(untenanted, instant(raisedAt)); !errors.Is(err, alert.ErrNoTenant) {
		t.Errorf("a detection with no tenant raised %v", err)
	}
}

func TestTheFloorIsReadOffTheContractAndNothingBelowItBecomesWork(t *testing.T) {
	floor, err := alert.ParseFloor("Medium")
	if err != nil {
		t.Fatalf("parse floor: %v", err)
	}
	if floor != detectionv1.Severity_SEVERITY_MEDIUM {
		t.Fatalf("the floor parsed as %s", floor)
	}

	raisable := map[detectionv1.Severity]bool{
		detectionv1.Severity_SEVERITY_UNSPECIFIED: false,
		detectionv1.Severity_SEVERITY_LOW:         false,
		detectionv1.Severity_SEVERITY_MEDIUM:      true,
		detectionv1.Severity_SEVERITY_HIGH:        true,
		detectionv1.Severity_SEVERITY_CRITICAL:    true,
	}
	for severity, want := range raisable {
		if got := alert.Raisable(severity, floor); got != want {
			t.Errorf("%s above a medium floor is %v and should be %v", severity, got, want)
		}
	}

	if _, err := alert.ParseFloor("catastrophic"); err == nil {
		t.Error("a severity nobody declared was accepted as a floor")
	}
	if _, err := alert.ParseFloor("unspecified"); err == nil {
		t.Error("the unspecified severity was accepted as a floor")
	}
}
