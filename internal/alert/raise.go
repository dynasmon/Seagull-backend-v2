package alert

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// Who raised it. An alert's first line in the trail is not somebody's act, and
// saying that is better than leaving the actor blank in a record whose whole
// point is that every line has one.
const Platform = "platform"

var (
	ErrUnnamed  = errors.New("the detection is unnamed, and an alert is named by the detection it is about")
	ErrNoTenant = errors.New("the detection names no tenant, and an alert nobody can be scoped to is an alert nobody can read")
)

// How much a detection has to matter before it is put in front of a person.
//
// Parsed against the contract's own enum rather than against a list kept here,
// so a severity the platform can report is a floor an operator can set and the
// two cannot drift apart. The enum is declared in order and `buf breaking`
// refuses a renumbering, so comparing the values compares the severities.
func ParseFloor(written string) (detectionv1.Severity, error) {
	wanted := "SEVERITY_" + strings.ToUpper(strings.TrimSpace(written))
	value, known := detectionv1.Severity_value[wanted]
	if !known || detectionv1.Severity(value) == detectionv1.Severity_SEVERITY_UNSPECIFIED {
		return 0, fmt.Errorf("%q names no severity; there are %s", written, Severities())
	}
	return detectionv1.Severity(value), nil
}

func Severities() string {
	named := make([]string, 0, len(detectionv1.Severity_name))
	for value := detectionv1.Severity_SEVERITY_LOW; value <= detectionv1.Severity_SEVERITY_CRITICAL; value++ {
		named = append(named, Severity(value))
	}
	return strings.Join(named, ", ")
}

func Severity(value detectionv1.Severity) string {
	trimmed := strings.TrimPrefix(value.String(), "SEVERITY_")
	if trimmed == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(trimmed)
}

func Raisable(severity, floor detectionv1.Severity) bool {
	return severity != detectionv1.Severity_SEVERITY_UNSPECIFIED && severity >= floor
}

// The analytical half is copied out of the detection and never changes again;
// the operational half starts at the beginning and is a person's from here on.
// The alert is named by the detection, so re-deciding the same events against
// the same rule finds the alert that already exists rather than raising another.
func Raise(made *detectionv1.Detection, at time.Time) (*alertv1.Alert, error) {
	if made.GetDetectionId() == "" {
		return nil, ErrUnnamed
	}
	if made.GetOrigin().GetTenantId() == "" {
		return nil, ErrNoTenant
	}

	raised := timestamppb.New(at.UTC())
	return &alertv1.Alert{
		AlertId:       made.GetDetectionId(),
		SchemaVersion: SchemaVersion,
		TenantId:      made.GetOrigin().GetTenantId(),
		DetectionId:   made.GetDetectionId(),
		Rule:          cloneRule(made.GetRule()),
		Severity:      made.GetSeverity(),
		Technique:     cloneTechnique(made.GetTechnique()),
		EventClass:    made.GetEventClass(),
		AgentId:       made.GetOrigin().GetAgentId(),
		EventTime:     made.GetEventTime(),
		RaisedAt:      raised,
		State:         Open.Wire(),
		ChangedBy:     Platform,
		ChangedAt:     raised,
		Revision:      1,
	}, nil
}

func Raised(alert *alertv1.Alert) *alertv1.Transition {
	return &alertv1.Transition{
		AlertId:  alert.GetAlertId(),
		Revision: alert.GetRevision(),
		From:     alertv1.State_STATE_UNSPECIFIED,
		To:       alert.GetState(),
		Actor:    Platform,
		At:       alert.GetRaisedAt(),
		Note:     "raised by " + alert.GetRule().GetId(),
	}
}

// Copied rather than pointed at: an alert outlives the detection it was made
// from by as long as somebody takes to close it, so it may not share memory
// with the record it was decoded out of.
func cloneRule(rule *detectionv1.Rule) *detectionv1.Rule {
	cloned, _ := proto.Clone(rule).(*detectionv1.Rule)
	return cloned
}

func cloneTechnique(technique *detectionv1.Technique) *detectionv1.Technique {
	cloned, _ := proto.Clone(technique).(*detectionv1.Technique)
	return cloned
}

func Class(class eventv1.EventClass) string {
	trimmed := strings.TrimPrefix(class.String(), "EVENT_CLASS_")
	if trimmed == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(trimmed)
}
