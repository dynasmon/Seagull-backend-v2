package detectionstore

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The inverse of Project. The store is a materialisation of what crossed the
// backbone, so a detection read back out of it is the contract message again:
// the finding an analyst reads is the same record the engine published.
func Restore(row Row) *detectionv1.Detection {
	made := &detectionv1.Detection{
		DetectionId:   row.DetectionID,
		SchemaVersion: row.SchemaVersion,
		Rule: &detectionv1.Rule{
			Id:       row.RuleID,
			Revision: row.RuleRevision,
			Name:     row.RuleName,
			Source: &detectionv1.Source{
				Catalogue:  row.RuleSourceCatalogue,
				Identifier: row.RuleSourceIdentifier,
			},
		},
		RulesetId: row.RulesetID,
		Severity:  detectionv1.Severity(enum(detectionv1.Severity_value, "SEVERITY_", row.Severity)),
		Technique: &detectionv1.Technique{
			Tactic: row.TechniqueTactic,
			Id:     row.TechniqueID,
			Name:   row.TechniqueName,
		},
		EventClass: eventv1.EventClass(enum(eventv1.EventClass_value, "EVENT_CLASS_", row.EventClass)),
		Origin: &eventv1.Origin{
			TenantId: row.TenantID,
			AgentId:  row.AgentID,
			Host: &eventv1.Host{
				Hostname:     row.HostHostname,
				Ip:           row.HostIP,
				Os:           row.HostOS,
				Architecture: row.HostArchitecture,
			},
		},
		SourceEventIds: row.SourceEventIDs,
		EventTime:      moment(row.EventTime),
		DetectedTime:   moment(row.DetectedTime),
	}

	made.Evidence = evidence(row)
	made.Aggregation = aggregation(row)
	made.Correlation = correlation(row)
	return made
}

func correlation(row Row) *detectionv1.Correlation {
	width := min(len(row.CorrelationStageName), len(row.CorrelationStageEventID), len(row.CorrelationStageEventTime))
	if width == 0 {
		return nil
	}

	told := &detectionv1.Correlation{
		Window:      durationpb.New(time.Duration(row.CorrelationWindowSeconds) * time.Second),
		ClockSpread: durationpb.New(time.Duration(row.CorrelationClockSpreadMillis) * time.Millisecond),
	}
	for index := range width {
		told.Stages = append(told.Stages, &detectionv1.Stage{
			Name:      row.CorrelationStageName[index],
			EventId:   row.CorrelationStageEventID[index],
			EventTime: moment(row.CorrelationStageEventTime[index]),
		})
	}

	grouped := min(len(row.CorrelationGroupField), len(row.CorrelationGroupValue), len(row.CorrelationGroupAbsent))
	for index := range grouped {
		told.Group = append(told.Group, &detectionv1.Grouping{
			Field:  row.CorrelationGroupField[index],
			Value:  row.CorrelationGroupValue[index],
			Absent: row.CorrelationGroupAbsent[index],
		})
	}
	return told
}

// A threshold is at least two, so a stored zero is a detection made by a rule
// that counts nothing rather than one whose count happened to be empty. Reading
// an aggregation onto it would say a rule counted when it did not.
func aggregation(row Row) *detectionv1.Aggregation {
	if row.AggregationThreshold == 0 {
		return nil
	}

	counted := &detectionv1.Aggregation{
		Count:          row.AggregationCount,
		Threshold:      row.AggregationThreshold,
		Window:         durationpb.New(time.Duration(row.AggregationWindowSeconds) * time.Second),
		FirstEventTime: moment(row.AggregationFirstEventTime),
		Saturated:      row.AggregationSaturated,
	}

	width := min(len(row.AggregationGroupField), len(row.AggregationGroupValue), len(row.AggregationGroupAbsent))
	for index := range width {
		counted.Group = append(counted.Group, &detectionv1.Grouping{
			Field:  row.AggregationGroupField[index],
			Value:  row.AggregationGroupValue[index],
			Absent: row.AggregationGroupAbsent[index],
		})
	}
	return counted
}

// The five arrays are one table read sideways, and a store that returned them at
// different lengths is a store that lost part of a row: read only as far as all
// five reach rather than inventing the remainder.
func evidence(row Row) []*detectionv1.Evidence {
	width := min(len(row.EvidenceField), len(row.EvidenceOperator), len(row.EvidenceNegated),
		len(row.EvidenceHeld), len(row.EvidenceAbsent))
	if width == 0 {
		return nil
	}

	seen := make([]*detectionv1.Evidence, 0, width)
	for index := range width {
		seen = append(seen, &detectionv1.Evidence{
			Field:    row.EvidenceField[index],
			Operator: row.EvidenceOperator[index],
			Negated:  row.EvidenceNegated[index],
			Held:     row.EvidenceHeld[index],
			Absent:   row.EvidenceAbsent[index],
		})
	}
	return seen
}

// The store writes an enumeration the way a person says it and writes nothing at
// all for the zero value, so the name is rebuilt from the contract rather than
// from a table this file would have to keep in step.
func enum(declared map[string]int32, prefix, stored string) int32 {
	if stored == "" {
		return 0
	}
	return declared[prefix+strings.ToUpper(stored)]
}

func moment(at time.Time) *timestamppb.Timestamp {
	if at.IsZero() || at.Equal(epoch) {
		return nil
	}
	return timestamppb.New(at)
}
