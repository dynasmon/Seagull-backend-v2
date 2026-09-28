package detection

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	MaxDetectionBytes = 256 << 10
	MaxEvidence       = 4096
)

func ValidateContract(made *detectionv1.Detection) error {
	if made == nil {
		return invalid("detection", "is missing")
	}
	if size := proto.Size(made); size > MaxDetectionBytes {
		return invalid("detection", fmt.Sprintf("encodes to %d bytes and the ceiling is %d", size, MaxDetectionBytes))
	}
	if err := contractIdentifier("detection_id", made.GetDetectionId()); err != nil {
		return err
	}
	if made.GetSchemaVersion() != SchemaVersion {
		return invalid("schema_version", fmt.Sprintf("must be %d", SchemaVersion))
	}
	if err := validateDecidingRule(made.GetRule()); err != nil {
		return err
	}
	if err := contractIdentifier("ruleset_id", made.GetRulesetId()); err != nil {
		return err
	}
	if made.GetSeverity() == detectionv1.Severity_SEVERITY_UNSPECIFIED {
		return invalid("severity", "is unspecified")
	}
	if _, declared := detectionv1.Severity_name[int32(made.GetSeverity())]; !declared {
		return invalid("severity", "is not a value the contract declares")
	}
	if err := validateDecidingTechnique(made.GetTechnique()); err != nil {
		return err
	}
	if made.GetEventClass() == eventv1.EventClass_EVENT_CLASS_UNSPECIFIED {
		return invalid("event_class", "is unspecified")
	}
	if _, declared := eventv1.EventClass_name[int32(made.GetEventClass())]; !declared {
		return invalid("event_class", "is not a value the contract declares")
	}
	if err := event.ValidateOrigin(made.GetOrigin()); err != nil {
		return err
	}
	if err := sourceEvents(made.GetSourceEventIds()); err != nil {
		return err
	}
	if err := contractInstant("event_time", made.GetEventTime()); err != nil {
		return err
	}
	if err := contractInstant("detected_time", made.GetDetectedTime()); err != nil {
		return err
	}
	if err := evidence(made.GetEvidence(), made.GetEventClass()); err != nil {
		return err
	}
	if made.GetAggregation() != nil && made.GetCorrelation() != nil {
		return invalid("detection", "carries both an aggregation and a correlation")
	}
	if err := aggregation(made.GetAggregation(), made.GetEventClass(), made.GetEventTime().AsTime()); err != nil {
		return err
	}
	return correlation(made.GetCorrelation(), made.GetEventClass(), made.GetSourceEventIds(), made.GetEventTime().AsTime())
}

func validateDecidingTechnique(held *detectionv1.Technique) error {
	if held == nil || held.GetTactic() == "" && held.GetId() == "" && held.GetName() == "" {
		return nil
	}
	if held.GetTactic() == "" || held.GetId() == "" || held.GetName() == "" {
		return invalid("technique", "needs a tactic, an id and a name, or none of the three")
	}
	if _, declared := tactics[held.GetTactic()]; !declared {
		return invalid("technique.tactic", "is not an ATT&CK enterprise tactic")
	}
	if !technique.MatchString(held.GetId()) {
		return invalid("technique.id", "is not an ATT&CK technique identifier")
	}
	return contractText("technique.name", held.GetName(), MaxNameLength, true)
}

func validateDecidingRule(rule *detectionv1.Rule) error {
	if rule == nil {
		return invalid("rule", "is missing")
	}
	if !identifier.MatchString(rule.GetId()) || len(rule.GetId()) > MaxIDLength || versioned.MatchString(rule.GetId()) {
		return invalid("rule.id", "is not a stable rule identifier")
	}
	if rule.GetRevision() == 0 {
		return invalid("rule.revision", "must be at least 1")
	}
	if err := contractText("rule.name", rule.GetName(), MaxNameLength, true); err != nil {
		return err
	}
	source := rule.GetSource()
	if source == nil {
		return nil
	}
	if (source.GetCatalogue() == "") != (source.GetIdentifier() == "") {
		return invalid("rule.source", "needs a catalogue and an identifier, or neither")
	}
	if source.GetCatalogue() == "" {
		return nil
	}
	if !identifier.MatchString(source.GetCatalogue()) || len(source.GetCatalogue()) > MaxIDLength {
		return invalid("rule.source.catalogue", "is not a catalogue identifier")
	}
	return contractText("rule.source.identifier", source.GetIdentifier(), MaxNameLength, true)
}

func sourceEvents(ids []string) error {
	if len(ids) == 0 {
		return invalid("source_event_ids", "names no event")
	}
	if len(ids) > MaxStages {
		return invalid("source_event_ids", fmt.Sprintf("names %d events and the ceiling is %d", len(ids), MaxStages))
	}
	seen := make(map[string]struct{}, len(ids))
	for index, id := range ids {
		field := fmt.Sprintf("source_event_ids[%d]", index)
		if !event.ValidIdentifier(id) {
			return invalid(field, "is malformed")
		}
		if _, repeated := seen[id]; repeated {
			return invalid(field, "names an event twice")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func evidence(found []*detectionv1.Evidence, class eventv1.EventClass) error {
	if len(found) > MaxEvidence {
		return invalid("evidence", fmt.Sprintf("carries %d entries and the ceiling is %d", len(found), MaxEvidence))
	}
	for index, one := range found {
		field := fmt.Sprintf("evidence[%d]", index)
		if one == nil {
			return invalid(field, "is missing")
		}
		path := Field(one.GetField())
		if _, declared := KindOf(path); !declared || !AddressableBy(path, class) {
			return invalid(field+".field", "is not addressable by this event class")
		}
		if !Operator(one.GetOperator()).known() {
			return invalid(field+".operator", "is not an operator the rule language declares")
		}
		if err := contractText(field+".held", one.GetHeld(), event.MaxRawRecordLength, false); err != nil {
			return err
		}
		if one.GetAbsent() && one.GetHeld() != "" {
			return invalid(field+".held", "is set for an absent field")
		}
	}
	return nil
}

func aggregation(counted *detectionv1.Aggregation, class eventv1.EventClass, eventTime time.Time) error {
	if counted == nil {
		return nil
	}
	if counted.GetThreshold() < MinCount || counted.GetThreshold() > MaxCount {
		return invalid("aggregation.threshold", fmt.Sprintf("must be between %d and %d", MinCount, MaxCount))
	}
	if counted.GetCount() < counted.GetThreshold() || counted.GetCount() > MaxCount {
		return invalid("aggregation.count", "is below the threshold or above the window ceiling")
	}
	window, err := contractDuration("aggregation.window", counted.GetWindow(), true)
	if err != nil {
		return err
	}
	if window > MaxWithin {
		return invalid("aggregation.window", fmt.Sprintf("is longer than %s", MaxWithin))
	}
	if err := contractInstant("aggregation.first_event_time", counted.GetFirstEventTime()); err != nil {
		return err
	}
	first := counted.GetFirstEventTime().AsTime()
	if first.After(eventTime) || eventTime.Sub(first) > window {
		return invalid("aggregation.first_event_time", "does not fall inside the aggregation window")
	}
	return groupings("aggregation.group", counted.GetGroup(), class)
}

func correlation(told *detectionv1.Correlation, class eventv1.EventClass, sourceIDs []string, eventTime time.Time) error {
	if told == nil {
		if len(sourceIDs) != 1 {
			return invalid("source_event_ids", "must name one event for an uncorrelated detection")
		}
		return nil
	}
	if len(told.GetStages()) < MinStages || len(told.GetStages()) > MaxStages {
		return invalid("correlation.stages", fmt.Sprintf("must name between %d and %d stages", MinStages, MaxStages))
	}
	if len(sourceIDs) != len(told.GetStages()) {
		return invalid("source_event_ids", "does not match the correlated stages")
	}
	window, err := contractDuration("correlation.window", told.GetWindow(), true)
	if err != nil {
		return err
	}
	if window > MaxWithin {
		return invalid("correlation.window", fmt.Sprintf("is longer than %s", MaxWithin))
	}
	spread, err := contractDuration("correlation.clock_spread", told.GetClockSpread(), false)
	if err != nil {
		return err
	}
	if spread < 0 {
		return invalid("correlation.clock_spread", "is negative")
	}

	names := make(map[string]struct{}, len(told.GetStages()))
	var first, previous time.Time
	for index, stage := range told.GetStages() {
		field := fmt.Sprintf("correlation.stages[%d]", index)
		if stage == nil {
			return invalid(field, "is missing")
		}
		if err := contractText(field+".name", stage.GetName(), MaxStageLength, true); err != nil {
			return err
		}
		if _, repeated := names[stage.GetName()]; repeated {
			return invalid(field+".name", "is repeated")
		}
		names[stage.GetName()] = struct{}{}
		if stage.GetEventId() != sourceIDs[index] {
			return invalid(field+".event_id", "does not match source_event_ids")
		}
		if err := contractInstant(field+".event_time", stage.GetEventTime()); err != nil {
			return err
		}
		at := stage.GetEventTime().AsTime()
		if index == 0 {
			first = at
		}
		if index > 0 && at.Before(previous) {
			return invalid(field+".event_time", "is before the previous stage")
		}
		previous = at
	}
	if previous != eventTime {
		return invalid("event_time", "does not equal the last correlated stage")
	}
	if previous.Sub(first) > window {
		return invalid("correlation.stages", "span longer than the correlation window")
	}
	return groupings("correlation.group", told.GetGroup(), class)
}

func groupings(field string, group []*detectionv1.Grouping, class eventv1.EventClass) error {
	if len(group) > MaxGroupBy {
		return invalid(field, fmt.Sprintf("names %d fields and the ceiling is %d", len(group), MaxGroupBy))
	}
	seen := make(map[Field]struct{}, len(group))
	for index, one := range group {
		part := fmt.Sprintf("%s[%d]", field, index)
		if one == nil {
			return invalid(part, "is missing")
		}
		path := Field(one.GetField())
		if _, declared := KindOf(path); !declared || !AddressableBy(path, class) {
			return invalid(part+".field", "is not addressable by this event class")
		}
		if _, repeated := seen[path]; repeated {
			return invalid(part+".field", "is repeated")
		}
		seen[path] = struct{}{}
		if err := contractText(part+".value", one.GetValue(), event.MaxRawRecordLength, false); err != nil {
			return err
		}
		if one.GetAbsent() && one.GetValue() != "" {
			return invalid(part+".value", "is set for an absent field")
		}
	}
	return nil
}

func contractInstant(field string, value *timestamppb.Timestamp) error {
	if value == nil {
		return invalid(field, "is missing")
	}
	if !value.IsValid() {
		return invalid(field, "is not a representable instant")
	}
	return nil
}

func contractDuration(field string, value *durationpb.Duration, positive bool) (time.Duration, error) {
	if value == nil {
		return 0, invalid(field, "is missing")
	}
	if err := value.CheckValid(); err != nil {
		return 0, invalid(field, "is not a representable duration")
	}
	duration := value.AsDuration()
	if positive && duration <= 0 {
		return 0, invalid(field, "must be positive")
	}
	return duration, nil
}

func contractText(field, value string, limit int, required bool) error {
	if !utf8.ValidString(value) {
		return invalid(field, "is not UTF-8")
	}
	if required && strings.TrimSpace(value) == "" {
		return invalid(field, "is missing")
	}
	if len(value) > limit {
		return invalid(field, fmt.Sprintf("is longer than %d bytes", limit))
	}
	return nil
}

func contractIdentifier(field, value string) error {
	if !event.ValidIdentifier(value) {
		return invalid(field, "is missing or malformed")
	}
	return nil
}

func invalid(field, reason string) error {
	return &event.Violation{Field: field, Reason: reason}
}
