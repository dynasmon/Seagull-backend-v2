package detectionstore

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

// The contract reaches the year 9999 and the store does not. Outside these
// bounds UnixNano wraps silently instead of failing.
var (
	epoch    = time.Unix(0, 0).UTC()
	earliest = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)
	latest   = time.Date(2262, time.April, 11, 23, 47, 16, 0, time.UTC)
)

// One row per detection, projected from the contract.
//
// The evidence arrives as a list and is kept as parallel arrays rather than as a
// document: what a rule read is a field path from the contract and what the
// event held is a value, and both are worth filtering on. v1 kept the equivalent
// in a JSON column and nothing could query it.
type Row struct {
	DetectionID   string
	SchemaVersion uint32

	RuleID               string
	RuleRevision         uint32
	RuleName             string
	RuleSourceCatalogue  string
	RuleSourceIdentifier string
	RulesetID            string

	Severity        string
	TechniqueTactic string
	TechniqueID     string
	TechniqueName   string

	EventClass       string
	TenantID         string
	AgentID          string
	HostHostname     string
	HostIP           string
	HostOS           string
	HostArchitecture string

	SourceEventIDs []string
	EventTime      time.Time
	DetectedTime   time.Time

	EvidenceField    []string
	EvidenceOperator []string
	EvidenceNegated  []bool
	EvidenceHeld     []string
	EvidenceAbsent   []bool
}

// Every contract leaf this projection keeps. A field added to the contract fails
// the coverage test until it is listed here, which is the rule that runs from
// the contract towards the store and never the other way.
var carried = []string{
	"detected_time",
	"detection_id",
	"event_class",
	"event_time",
	"evidence.absent",
	"evidence.field",
	"evidence.held",
	"evidence.negated",
	"evidence.operator",
	"origin.agent_id",
	"origin.host.architecture",
	"origin.host.hostname",
	"origin.host.ip",
	"origin.host.os",
	"origin.tenant_id",
	"rule.id",
	"rule.name",
	"rule.revision",
	"rule.source.catalogue",
	"rule.source.identifier",
	"ruleset_id",
	"schema_version",
	"severity",
	"source_event_ids",
	"technique.id",
	"technique.name",
	"technique.tactic",
}

func Project(made *detectionv1.Detection) Row {
	row := Row{
		DetectionID:   made.GetDetectionId(),
		SchemaVersion: made.GetSchemaVersion(),

		RuleID:               made.GetRule().GetId(),
		RuleRevision:         made.GetRule().GetRevision(),
		RuleName:             made.GetRule().GetName(),
		RuleSourceCatalogue:  made.GetRule().GetSource().GetCatalogue(),
		RuleSourceIdentifier: made.GetRule().GetSource().GetIdentifier(),
		RulesetID:            made.GetRulesetId(),

		Severity:        name(made.GetSeverity().String(), "SEVERITY_"),
		TechniqueTactic: made.GetTechnique().GetTactic(),
		TechniqueID:     made.GetTechnique().GetId(),
		TechniqueName:   made.GetTechnique().GetName(),

		EventClass:       name(made.GetEventClass().String(), "EVENT_CLASS_"),
		TenantID:         made.GetOrigin().GetTenantId(),
		AgentID:          made.GetOrigin().GetAgentId(),
		HostHostname:     made.GetOrigin().GetHost().GetHostname(),
		HostIP:           made.GetOrigin().GetHost().GetIp(),
		HostOS:           made.GetOrigin().GetHost().GetOs(),
		HostArchitecture: made.GetOrigin().GetHost().GetArchitecture(),

		SourceEventIDs: made.GetSourceEventIds(),
		EventTime:      instant(made.GetEventTime()),
		DetectedTime:   instant(made.GetDetectedTime()),
	}

	// The five arrays are one table read sideways, so they are filled together
	// and are the same length by construction. A reader that zips them is
	// entitled to assume that, and `storable` refuses a row where it is untrue.
	seen := made.GetEvidence()
	row.EvidenceField = make([]string, 0, len(seen))
	row.EvidenceOperator = make([]string, 0, len(seen))
	row.EvidenceNegated = make([]bool, 0, len(seen))
	row.EvidenceHeld = make([]string, 0, len(seen))
	row.EvidenceAbsent = make([]bool, 0, len(seen))
	for _, one := range seen {
		row.EvidenceField = append(row.EvidenceField, one.GetField())
		row.EvidenceOperator = append(row.EvidenceOperator, one.GetOperator())
		row.EvidenceNegated = append(row.EvidenceNegated, one.GetNegated())
		row.EvidenceHeld = append(row.EvidenceHeld, one.GetHeld())
		row.EvidenceAbsent = append(row.EvidenceAbsent, one.GetAbsent())
	}

	if row.SourceEventIDs == nil {
		row.SourceEventIDs = []string{}
	}
	return row
}

func name(value, prefix string) string {
	trimmed := strings.TrimPrefix(value, prefix)
	if trimmed == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(trimmed)
}

// Absent is the epoch, not the year one, which the column cannot hold.
func instant(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return epoch
	}
	return value.AsTime().UTC()
}

// Checked before the batch is built, so one unrepresentable record is refused to
// quarantine rather than failing the batch it shares.
func storable(row Row) error {
	if row.DetectionID == "" {
		return fmt.Errorf("detection_id is empty, and a detection is named by what decided it")
	}
	if err := representable("event_time", row.EventTime); err != nil {
		return err
	}
	if err := representable("detected_time", row.DetectedTime); err != nil {
		return err
	}

	widths := map[string]int{
		"evidence.field":    len(row.EvidenceField),
		"evidence.operator": len(row.EvidenceOperator),
		"evidence.negated":  len(row.EvidenceNegated),
		"evidence.held":     len(row.EvidenceHeld),
		"evidence.absent":   len(row.EvidenceAbsent),
	}
	for field, width := range widths {
		if width != len(row.EvidenceField) {
			return fmt.Errorf("%s carries %d entries and evidence.field carries %d: the arrays are one table read sideways",
				field, width, len(row.EvidenceField))
		}
	}
	return nil
}

func representable(field string, at time.Time) error {
	if at.Before(earliest) || at.After(latest) {
		return fmt.Errorf("%s is outside the %s..%s the store can hold",
			field, earliest.Format(time.DateOnly), latest.Format(time.DateOnly))
	}
	return nil
}
