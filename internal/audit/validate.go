package audit

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

var (
	earliest = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)
	latest   = time.Date(2262, time.April, 11, 23, 47, 16, 0, time.UTC)
)

// An event outside the contract is refused whole: it is chained as it was
// published, so nothing is trimmed to fit. An action, an outcome or a kind of
// actor this build does not name is refused too, because a review asks for one
// of them by name and could never find it.
func Validate(recorded *auditv1.Event) error {
	if recorded == nil {
		return &event.Violation{Field: "event", Reason: "is missing"}
	}
	if version := recorded.GetSchemaVersion(); version < MinSchemaVersion || version > MaxSchemaVersion {
		return &event.Violation{Field: "schema_version", Reason: fmt.Sprintf("must be between %d and %d", MinSchemaVersion, MaxSchemaVersion)}
	}
	if !identifier(recorded.GetEventId()) {
		return &event.Violation{Field: "event_id", Reason: fmt.Sprintf("is not lowercase hex of at most %d bytes", MaxEventIDLength)}
	}
	if err := text("tenant_id", recorded.GetTenantId(), event.MaxTenantIDLength, false); err != nil {
		return err
	}
	if err := instant("occurred_at", recorded.GetOccurredAt(), true); err != nil {
		return err
	}
	if err := actor(recorded.GetActor()); err != nil {
		return err
	}
	if _, named := auditv1.Event_Action_name[int32(recorded.GetAction())]; !named || recorded.GetAction() == auditv1.Event_ACTION_UNSPECIFIED {
		return &event.Violation{Field: "action", Reason: "is not an action this build records"}
	}
	if err := target(recorded.GetTarget()); err != nil {
		return err
	}
	if err := outcome(recorded); err != nil {
		return err
	}
	if err := text("reason", recorded.GetReason(), MaxReasonLength, false); err != nil {
		return err
	}
	if err := origin(recorded.GetOrigin()); err != nil {
		return err
	}
	if err := text("change.before", recorded.GetChange().GetBefore(), MaxChangeLength, false); err != nil {
		return err
	}
	if err := text("change.after", recorded.GetChange().GetAfter(), MaxChangeLength, false); err != nil {
		return err
	}
	if err := question(recorded); err != nil {
		return err
	}
	if size := proto.Size(recorded); size > MaxEventBytes {
		return &event.Violation{Field: "event", Reason: fmt.Sprintf("encodes to %d bytes and the ceiling is %d", size, MaxEventBytes)}
	}
	return nil
}

func ActionName(action auditv1.Event_Action) string {
	name, declared := auditv1.Event_Action_name[int32(action)]
	if !declared {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(name, "ACTION_"))
}

func actor(acting *auditv1.Event_Actor) error {
	switch acting.GetKind() {
	case auditv1.Event_Actor_KIND_OPERATOR, auditv1.Event_Actor_KIND_AGENT, auditv1.Event_Actor_KIND_PLATFORM:
	default:
		return &event.Violation{Field: "actor.kind", Reason: "is not a kind of actor this build records"}
	}
	if err := text("actor.subject", acting.GetSubject(), MaxSubjectLength, true); err != nil {
		return err
	}
	return text("actor.session_id", acting.GetSessionId(), MaxSessionIDLength, false)
}

func target(about *auditv1.Event_Target) error {
	if _, named := controlv1.Resource_name[int32(about.GetResource())]; !named || about.GetResource() == controlv1.Resource_RESOURCE_UNSPECIFIED {
		return &event.Violation{Field: "target.resource", Reason: "is not a resource this build names"}
	}
	return text("target.id", about.GetId(), MaxTargetIDLength, false)
}

func outcome(recorded *auditv1.Event) error {
	switch recorded.GetOutcome() {
	case auditv1.Event_OUTCOME_SUCCEEDED:
		if recorded.GetCode() != "" {
			return &event.Violation{Field: "code", Reason: "is set on an action that succeeded"}
		}
		return nil
	case auditv1.Event_OUTCOME_FAILED, auditv1.Event_OUTCOME_DENIED:
		return text("code", recorded.GetCode(), MaxCodeLength, false)
	default:
		return &event.Violation{Field: "outcome", Reason: "is not an outcome this build records"}
	}
}

func origin(from *auditv1.Event_Origin) error {
	if err := text("origin.component", from.GetComponent(), MaxComponentLength, true); err != nil {
		return err
	}
	if err := text("origin.request_id", from.GetRequestId(), MaxRequestIDLength, false); err != nil {
		return err
	}
	return text("origin.address", from.GetAddress(), MaxAddressLength, false)
}

func question(recorded *auditv1.Event) error {
	asked := recorded.GetQuestion()
	if recorded.GetAction() != auditv1.Event_ACTION_QUESTION_ASKED {
		if asked != nil {
			return &event.Violation{Field: "question", Reason: "is set on an action that asked nothing"}
		}
		return nil
	}
	if asked == nil {
		return &event.Violation{Field: "question", Reason: "is missing from a question asked"}
	}
	if err := text("question.dataset", asked.GetDataset(), MaxDatasetLength, true); err != nil {
		return err
	}
	return window(asked.GetRange())
}

func window(asked *huntv1.TimeRange) error {
	if asked == nil {
		return &event.Violation{Field: "question.range", Reason: "is missing"}
	}
	if err := instant("question.range.start", asked.GetStart(), true); err != nil {
		return err
	}
	if err := instant("question.range.end", asked.GetEnd(), true); err != nil {
		return err
	}
	if asked.GetEnd().AsTime().Before(asked.GetStart().AsTime()) {
		return &event.Violation{Field: "question.range", Reason: "ends before it starts"}
	}
	return nil
}

func identifier(value string) bool {
	if value == "" || len(value) > MaxEventIDLength {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func instant(field string, value *timestamppb.Timestamp, required bool) error {
	if value == nil {
		if required {
			return &event.Violation{Field: field, Reason: "is missing"}
		}
		return nil
	}
	if !value.IsValid() {
		return &event.Violation{Field: field, Reason: "is not a representable instant"}
	}
	if at := value.AsTime(); at.Before(earliest) || at.After(latest) {
		return &event.Violation{Field: field, Reason: "is outside the instants the platform can hold"}
	}
	return nil
}

func text(field, value string, maximum int, required bool) error {
	if value == "" {
		if required {
			return &event.Violation{Field: field, Reason: "is required"}
		}
		return nil
	}
	if len(value) > maximum {
		return &event.Violation{Field: field, Reason: fmt.Sprintf("is longer than %d bytes", maximum)}
	}
	return nil
}
