package audit_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/audit"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

var occurred = time.Date(2026, time.November, 26, 9, 30, 0, 0, time.UTC)

func moved() *auditv1.Event {
	return &auditv1.Event{
		SchemaVersion: audit.SchemaVersion,
		EventId:       "9f2c4e1a",
		TenantId:      "tenant-a",
		OccurredAt:    timestamppb.New(occurred),
		Actor:         &auditv1.Event_Actor{Kind: auditv1.Event_Actor_KIND_OPERATOR, Subject: "alice", SessionId: "5e5510"},
		Action:        auditv1.Event_ACTION_ALERT_MOVED,
		Target:        &auditv1.Event_Target{Resource: controlv1.Resource_RESOURCE_ALERTS, Id: "alert-1"},
		Outcome:       auditv1.Event_OUTCOME_SUCCEEDED,
		Reason:        "contained",
		Origin:        &auditv1.Event_Origin{Component: "control-api", RequestId: "request-1", Address: "192.0.2.10"},
		Change:        &auditv1.Event_Change{Before: "open", After: "acknowledged"},
	}
}

func asked() *auditv1.Event {
	recorded := moved()
	recorded.Action = auditv1.Event_ACTION_QUESTION_ASKED
	recorded.Target = &auditv1.Event_Target{Resource: controlv1.Resource_RESOURCE_EVENTS}
	recorded.Origin.Component = "query-api"
	recorded.Change = nil
	recorded.Reason = ""
	recorded.Question = &auditv1.Event_Question{
		Dataset: "events",
		Range:   &huntv1.TimeRange{Start: timestamppb.New(occurred.Add(-time.Hour)), End: timestamppb.New(occurred)},
	}
	return recorded
}

func TestAnEventTheContractDescribesIsAccepted(t *testing.T) {
	for name, recorded := range map[string]*auditv1.Event{
		"a move":         moved(),
		"a question":     asked(),
		"the platform's": func() *auditv1.Event { e := moved(); e.TenantId = ""; return e }(),
		"a refusal": func() *auditv1.Event {
			e := moved()
			e.Outcome = auditv1.Event_OUTCOME_DENIED
			e.Code = "forbidden"
			return e
		}(),
		"an unnamed target": func() *auditv1.Event { e := moved(); e.Target.Id = ""; return e }(),
	} {
		if err := audit.Validate(recorded); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}

func TestAnEventOutsideTheContractIsRefusedByTheFieldThatIsWrong(t *testing.T) {
	for _, refused := range []struct {
		field  string
		change func(*auditv1.Event)
	}{
		{"schema_version", func(e *auditv1.Event) { e.SchemaVersion = 2 }},
		{"event_id", func(e *auditv1.Event) { e.EventId = "" }},
		{"event_id", func(e *auditv1.Event) { e.EventId = "9F2C4E1A" }},
		{"event_id", func(e *auditv1.Event) { e.EventId = strings.Repeat("a", audit.MaxEventIDLength+1) }},
		{"tenant_id", func(e *auditv1.Event) { e.TenantId = strings.Repeat("t", event.MaxTenantIDLength+1) }},
		{"occurred_at", func(e *auditv1.Event) { e.OccurredAt = nil }},
		{"occurred_at", func(e *auditv1.Event) { e.OccurredAt = &timestamppb.Timestamp{Nanos: -1} }},
		{"actor.kind", func(e *auditv1.Event) { e.Actor = nil }},
		{"actor.kind", func(e *auditv1.Event) { e.Actor.Kind = 9 }},
		{"actor.subject", func(e *auditv1.Event) { e.Actor.Subject = "" }},
		{"actor.subject", func(e *auditv1.Event) { e.Actor.Subject = strings.Repeat("s", audit.MaxSubjectLength+1) }},
		{"actor.session_id", func(e *auditv1.Event) { e.Actor.SessionId = strings.Repeat("5", audit.MaxSessionIDLength+1) }},
		{"action", func(e *auditv1.Event) { e.Action = auditv1.Event_ACTION_UNSPECIFIED }},
		{"action", func(e *auditv1.Event) { e.Action = 99 }},
		{"target.resource", func(e *auditv1.Event) { e.Target = nil }},
		{"target.resource", func(e *auditv1.Event) { e.Target.Resource = 99 }},
		{"target.id", func(e *auditv1.Event) { e.Target.Id = strings.Repeat("i", audit.MaxTargetIDLength+1) }},
		{"outcome", func(e *auditv1.Event) { e.Outcome = auditv1.Event_OUTCOME_UNSPECIFIED }},
		{"code", func(e *auditv1.Event) { e.Code = "forbidden" }},
		{"code", func(e *auditv1.Event) {
			e.Outcome = auditv1.Event_OUTCOME_FAILED
			e.Code = strings.Repeat("c", audit.MaxCodeLength+1)
		}},
		{"reason", func(e *auditv1.Event) { e.Reason = strings.Repeat("r", audit.MaxReasonLength+1) }},
		{"origin.component", func(e *auditv1.Event) { e.Origin = nil }},
		{"origin.request_id", func(e *auditv1.Event) { e.Origin.RequestId = strings.Repeat("q", audit.MaxRequestIDLength+1) }},
		{"origin.address", func(e *auditv1.Event) { e.Origin.Address = strings.Repeat("a", audit.MaxAddressLength+1) }},
		{"change.before", func(e *auditv1.Event) { e.Change.Before = strings.Repeat("b", audit.MaxChangeLength+1) }},
		{"change.after", func(e *auditv1.Event) { e.Change.After = strings.Repeat("a", audit.MaxChangeLength+1) }},
		{"question", func(e *auditv1.Event) { e.Question = asked().GetQuestion() }},
	} {
		recorded := moved()
		refused.change(recorded)
		assertRefusedFor(t, recorded, refused.field)
	}
}

func TestAQuestionNamesItsDatasetAndAWindowThatDoesNotEndBeforeItStarts(t *testing.T) {
	for _, refused := range []struct {
		field  string
		change func(*auditv1.Event)
	}{
		{"question", func(e *auditv1.Event) { e.Question = nil }},
		{"question.dataset", func(e *auditv1.Event) { e.Question.Dataset = "" }},
		{"question.dataset", func(e *auditv1.Event) { e.Question.Dataset = strings.Repeat("d", audit.MaxDatasetLength+1) }},
		{"question.range", func(e *auditv1.Event) { e.Question.Range = nil }},
		{"question.range.start", func(e *auditv1.Event) { e.Question.Range.Start = nil }},
		{"question.range.end", func(e *auditv1.Event) { e.Question.Range.End = nil }},
		{"question.range", func(e *auditv1.Event) {
			e.Question.Range.Start, e.Question.Range.End = e.Question.Range.End, e.Question.Range.Start
		}},
	} {
		recorded := asked()
		refused.change(recorded)
		assertRefusedFor(t, recorded, refused.field)
	}
}

func TestAnEventCarryingMoreThanTheContractAllowsIsRefusedByItsSize(t *testing.T) {
	recorded := moved()
	unknown := protowire.AppendTag(nil, 99, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, make([]byte, audit.MaxEventBytes))
	recorded.ProtoReflect().SetUnknown(unknown)
	assertRefusedFor(t, recorded, "event")

	if size := proto.Size(moved()); size > audit.MaxEventBytes {
		t.Fatalf("an ordinary event encodes to %d bytes, over the %d the contract allows", size, audit.MaxEventBytes)
	}
}

func TestAnActionIsNamedTheWayAReviewAsksForIt(t *testing.T) {
	for action, want := range map[auditv1.Event_Action]string{
		auditv1.Event_ACTION_SESSION_OPENED: "session_opened",
		auditv1.Event_ACTION_QUESTION_ASKED: "question_asked",
		99:                                  "unknown",
	} {
		if got := audit.ActionName(action); got != want {
			t.Errorf("%v is named %q, want %q", action, got, want)
		}
	}
}

func assertRefusedFor(t *testing.T, recorded *auditv1.Event, field string) {
	t.Helper()
	var violation *event.Violation
	err := audit.Validate(recorded)
	if !errors.As(err, &violation) {
		t.Errorf("an event wrong in %s was refused with %v", field, err)
		return
	}
	if violation.Field != field {
		t.Errorf("an event wrong in %s was refused for %s: %v", field, violation.Field, err)
	}
}
