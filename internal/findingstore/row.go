package findingstore

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

var epoch = time.Unix(0, 0).UTC()

// One decision about one finding, under the episode it belongs to: the columns
// a reader asks about, and the record itself, byte for byte as the matcher
// published it, which is what a reader is handed back.
type FindingRow struct {
	TenantID        string
	AgentID         string
	ItemID          string
	VulnerabilityID string
	OpenedAt        time.Time
	State           string

	InventoryAsOf    time.Time
	IntelligenceAsOf time.Time
	DecidedAt        time.Time

	Unassessable     string
	PackageName      string
	PackageVersion   string
	AdvisedEcosystem string
	AdvisedPackage   string
	Fix              string
	SeverityType     string
	SeverityScore    string

	Record []byte
}

type AssessmentRow struct {
	TenantID         string
	AgentID          string
	Scope            string
	InventoryAsOf    time.Time
	IntelligenceAsOf time.Time
	DecidedAt        time.Time

	Stale        bool
	Unassessable string
	Open         uint32
	Closed       uint32
	Unassessed   uint32

	Record []byte
}

func ProjectFinding(decided *vulnerabilityv1.Finding, published []byte) FindingRow {
	return FindingRow{
		TenantID:        decided.GetTenantId(),
		AgentID:         decided.GetAgentId(),
		ItemID:          decided.GetItemId(),
		VulnerabilityID: decided.GetVulnerabilityId(),
		OpenedAt:        instant(decided.GetOpenedAt()),
		State:           named(decided.GetState().String(), "FINDING_STATE_"),

		InventoryAsOf:    instant(decided.GetInventory().GetAsOf()),
		IntelligenceAsOf: instant(decided.GetIntelligence().GetAsOf()),
		DecidedAt:        instant(decided.GetDecidedAt()),

		Unassessable:     named(decided.GetUnassessable().String(), "UNASSESSABLE_"),
		PackageName:      decided.GetPackage().GetName(),
		PackageVersion:   decided.GetPackage().GetVersion(),
		AdvisedEcosystem: decided.GetAdvised().GetEcosystem(),
		AdvisedPackage:   decided.GetAdvised().GetName(),
		Fix:              decided.GetFix(),
		SeverityType:     named(decided.GetRating().GetSeverity().GetType().String(), "TYPE_"),
		SeverityScore:    decided.GetRating().GetSeverity().GetScore(),

		Record: published,
	}
}

func ProjectAssessment(assessed *vulnerabilityv1.Assessment, published []byte) AssessmentRow {
	row := AssessmentRow{
		TenantID:         assessed.GetTenantId(),
		AgentID:          assessed.GetAgentId(),
		Scope:            named(assessed.GetScope().String(), "SCOPE_"),
		InventoryAsOf:    instant(assessed.GetInventory().GetAsOf()),
		IntelligenceAsOf: instant(assessed.GetIntelligence().GetAsOf()),
		DecidedAt:        instant(assessed.GetDecidedAt()),

		Stale:        assessed.GetStale(),
		Unassessable: named(assessed.GetUnassessable().String(), "UNASSESSABLE_"),
		Open:         assessed.GetOpen(),
		Closed:       assessed.GetClosed(),

		Record: published,
	}
	for _, counted := range assessed.GetUnassessed() {
		row.Unassessed += counted.GetPackages()
	}
	return row
}

func named(value, prefix string) string {
	trimmed := strings.TrimPrefix(value, prefix)
	if trimmed == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(trimmed)
}

func instant(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return epoch
	}
	return value.AsTime().UTC()
}
