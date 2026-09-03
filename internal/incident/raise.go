package incident

import (
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

const Platform = "platform"

// What became of a correlation on its way to being somebody's work. Two things
// and not four: a story is told once per window that holds it, so there is
// nothing here to fold into and nothing to hold back.
type Outcome string

const (
	OutcomeRaised   Outcome = "raised"
	OutcomeRepeated Outcome = "repeated"
)

func (o Outcome) String() string { return string(o) }

var (
	ErrUnnamed  = errors.New("the detection is unnamed, and an incident is named by the correlation it is about")
	ErrNoTenant = errors.New("the detection names no tenant, and an incident nobody can be scoped to is an incident nobody can read")
	ErrNoStory  = errors.New("the detection carries no correlated stages, and an incident is a story or it is nothing")
)

// Whether this detection is a story several events tell together rather than a
// finding about one. It is the only thing that separates an incident from an
// alert on the way out of the analysis engine, and it is a property of the
// record rather than a setting.
func Correlates(made *detectionv1.Detection) bool {
	return len(made.GetCorrelation().GetStages()) > 0
}

// The analytical half is copied out of the correlation and never changes again;
// the operational half starts at the beginning and is a person's from here on.
// The incident is named by the detection that told the story, so re-deciding the
// same events against the same rule finds the incident that already exists
// rather than opening another.
func Raise(made *detectionv1.Detection, at time.Time) (*incidentv1.Incident, error) {
	switch {
	case made.GetDetectionId() == "":
		return nil, ErrUnnamed
	case made.GetOrigin().GetTenantId() == "":
		return nil, ErrNoTenant
	case !Correlates(made):
		return nil, ErrNoStory
	}

	correlation := made.GetCorrelation()
	told := cloneAll(correlation.GetStages())

	return &incidentv1.Incident{
		IncidentId:     made.GetDetectionId(),
		SchemaVersion:  SchemaVersion,
		TenantId:       made.GetOrigin().GetTenantId(),
		DetectionId:    made.GetDetectionId(),
		Rule:           clone(made.GetRule()),
		RulesetId:      made.GetRulesetId(),
		Severity:       made.GetSeverity(),
		Confidence:     Confidence(correlation),
		Technique:      clone(made.GetTechnique()),
		EventClass:     made.GetEventClass(),
		AgentId:        made.GetOrigin().GetAgentId(),
		Stages:         told,
		Group:          cloneAll(correlation.GetGroup()),
		Window:         clone(correlation.GetWindow()),
		ClockSpread:    clone(correlation.GetClockSpread()),
		FirstEventTime: told[0].GetEventTime(),
		LastEventTime:  told[len(told)-1].GetEventTime(),
		RaisedAt:       timestamppb.New(at.UTC()),
		State:          Open.Wire(),
		ChangedBy:      Platform,
		ChangedAt:      timestamppb.New(at.UTC()),
		Revision:       1,
	}, nil
}

func Raised(one *incidentv1.Incident) *incidentv1.Transition {
	return &incidentv1.Transition{
		IncidentId: one.GetIncidentId(),
		Revision:   one.GetRevision(),
		From:       incidentv1.State_STATE_UNSPECIFIED,
		To:         one.GetState(),
		Actor:      Platform,
		At:         one.GetRaisedAt(),
		Note:       "correlated by " + one.GetRule().GetId(),
	}
}

// Copied rather than pointed at: an incident outlives the detection it was made
// from by as long as somebody takes to close it, so it may not share memory with
// the record it was decoded out of.
func clone[T proto.Message](value T) T {
	copied, _ := proto.Clone(value).(T)
	return copied
}

func cloneAll[T proto.Message](values []T) []T {
	copied := make([]T, 0, len(values))
	for _, value := range values {
		copied = append(copied, clone(value))
	}
	return copied
}

func Severity(value detectionv1.Severity) string {
	trimmed := strings.TrimPrefix(value.String(), "SEVERITY_")
	if trimmed == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(trimmed)
}

func Class(class eventv1.EventClass) string {
	trimmed := strings.TrimPrefix(class.String(), "EVENT_CLASS_")
	if trimmed == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(trimmed)
}
