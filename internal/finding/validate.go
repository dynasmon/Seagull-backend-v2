package finding

import (
	"encoding/hex"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

func ValidateRecord(record *vulnerabilityv1.FindingRecord) error {
	switch body := record.GetRecord().(type) {
	case *vulnerabilityv1.FindingRecord_Finding:
		if err := Validate(body.Finding); err != nil {
			return err
		}
	case *vulnerabilityv1.FindingRecord_Assessment:
		if err := ValidateAssessment(body.Assessment); err != nil {
			return err
		}
	default:
		return &event.Violation{Field: "record", Reason: "carries neither a finding nor an assessment"}
	}
	if size := proto.Size(record); size > MaxRecordBytes {
		return &event.Violation{Field: "record", Reason: fmt.Sprintf("encodes to %d bytes and the ceiling is %d", size, MaxRecordBytes)}
	}
	return nil
}

// A decision is ordered and deduplicated by its name and its two instants, so
// none of them may be missing. Every decision but a cannot-assess one belongs
// to an episode of exposure, open or the one it closes, and names it by when
// it opened.
func Validate(decided *vulnerabilityv1.Finding) error {
	if decided == nil {
		return &event.Violation{Field: "finding", Reason: "is missing"}
	}
	if err := asset(decided.GetSchemaVersion(), decided.GetTenantId(), decided.GetAgentId()); err != nil {
		return err
	}
	if decoded, err := hex.DecodeString(decided.GetItemId()); err != nil || len(decided.GetItemId()) != ItemIDLength ||
		hex.EncodeToString(decoded) != decided.GetItemId() {
		return &event.Violation{Field: "item_id", Reason: "is not an inventory item identifier"}
	}
	if !vulnerability.Identifier(decided.GetVulnerabilityId()) {
		return &event.Violation{Field: "vulnerability_id", Reason: "is missing or malformed"}
	}

	state := decided.GetState()
	if err := declared("state", int32(state), vulnerabilityv1.FindingState_name, true); err != nil {
		return err
	}
	if err := declared("unassessable", int32(decided.GetUnassessable()), vulnerabilityv1.Unassessable_name, false); err != nil {
		return err
	}
	unassessed := state == vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS
	if unassessed != (decided.GetUnassessable() != vulnerabilityv1.Unassessable_UNASSESSABLE_UNSPECIFIED) {
		return &event.Violation{Field: "unassessable", Reason: "is set exactly when the platform could not assess"}
	}
	if err := instant("opened_at", decided.GetOpenedAt(), !unassessed); err != nil {
		return err
	}

	if err := installedPackage(decided.GetPackage()); err != nil {
		return err
	}
	advised := decided.GetAdvised()
	if named, err := vulnerability.Ecosystem(advised.GetEcosystem()); err != nil || named != advised.GetEcosystem() {
		return &event.Violation{Field: "advised.ecosystem", Reason: "is not an ecosystem as the platform names it"}
	}
	for _, field := range []struct {
		name     string
		value    string
		maximum  int
		required bool
	}{
		{"advised.name", advised.GetName(), vulnerability.MaxPackageLength, true},
		{"compared_version", decided.GetComparedVersion(), vulnerability.MaxVersionLength, true},
		{"fix", decided.GetFix(), vulnerability.MaxVersionLength, false},
	} {
		if err := text(field.name, field.value, field.maximum, field.required); err != nil {
			return err
		}
	}

	if err := citations(decided.GetCitations()); err != nil {
		return err
	}
	if err := rating(decided.GetRating()); err != nil {
		return err
	}
	if err := inventoryBasis(decided.GetInventory(), true); err != nil {
		return err
	}
	if err := intelligenceBasis(decided.GetIntelligence(), true); err != nil {
		return err
	}
	return instant("decided_at", decided.GetDecidedAt(), true)
}

func ValidateAssessment(assessed *vulnerabilityv1.Assessment) error {
	if assessed == nil {
		return &event.Violation{Field: "assessment", Reason: "is missing"}
	}
	if err := asset(assessed.GetSchemaVersion(), assessed.GetTenantId(), assessed.GetAgentId()); err != nil {
		return err
	}
	if err := declared("scope", int32(assessed.GetScope()), vulnerabilityv1.Assessment_Scope_name, true); err != nil {
		return err
	}
	if err := declared("unassessable", int32(assessed.GetUnassessable()), vulnerabilityv1.Unassessable_name, false); err != nil {
		return err
	}

	unassessed := assessed.GetUnassessed()
	if len(unassessed) > len(vulnerabilityv1.Unassessable_name)-1 {
		return &event.Violation{Field: "unassessed", Reason: "counts more reasons than the contract declares"}
	}
	seen := map[vulnerabilityv1.Unassessable]bool{}
	for index, counted := range unassessed {
		field := fmt.Sprintf("unassessed[%d]", index)
		if err := declared(field+".reason", int32(counted.GetReason()), vulnerabilityv1.Unassessable_name, true); err != nil {
			return err
		}
		if seen[counted.GetReason()] {
			return &event.Violation{Field: field + ".reason", Reason: "is counted twice"}
		}
		seen[counted.GetReason()] = true
		if counted.GetPackages() == 0 {
			return &event.Violation{Field: field + ".packages", Reason: "counts no package"}
		}
	}

	if err := inventoryBasis(assessed.GetInventory(), false); err != nil {
		return err
	}
	if err := intelligenceBasis(assessed.GetIntelligence(), false); err != nil {
		return err
	}
	return instant("decided_at", assessed.GetDecidedAt(), true)
}

func asset(schemaVersion uint32, tenantID, agentID string) error {
	if schemaVersion < MinSchemaVersion || schemaVersion > MaxSchemaVersion {
		return &event.Violation{
			Field:  "schema_version",
			Reason: fmt.Sprintf("must be between %d and %d", MinSchemaVersion, MaxSchemaVersion),
		}
	}
	if err := text("tenant_id", tenantID, event.MaxTenantIDLength, true); err != nil {
		return err
	}
	if !agentidentity.Valid(agentID) {
		return &event.Violation{Field: "agent_id", Reason: "is missing or malformed"}
	}
	return nil
}

func installedPackage(installed *inventoryv1.Package) error {
	if installed == nil {
		return &event.Violation{Field: "package", Reason: "is missing"}
	}
	for _, field := range []struct {
		name     string
		value    string
		maximum  int
		required bool
	}{
		{"package.name", installed.GetName(), inventory.MaxNameLength, true},
		{"package.version", installed.GetVersion(), inventory.MaxVersionLength, true},
		{"package.architecture", installed.GetArchitecture(), inventory.MaxArchitectureLength, false},
		{"package.manager", installed.GetManager(), inventory.MaxManagerLength, true},
		{"package.source", installed.GetSource(), inventory.MaxSourceLength, false},
		{"package.vendor", installed.GetVendor(), inventory.MaxVendorLength, false},
	} {
		if err := text(field.name, field.value, field.maximum, field.required); err != nil {
			return err
		}
	}
	return instant("package.installed_at", installed.GetInstalledAt(), false)
}

func citations(cited []*vulnerabilityv1.Citation) error {
	if len(cited) > MaxCitations {
		return &event.Violation{Field: "citations", Reason: fmt.Sprintf("cites %d advisories and the ceiling is %d", len(cited), MaxCitations)}
	}
	for index, citation := range cited {
		field := fmt.Sprintf("citations[%d]", index)
		if err := advisoryName(field, citation.GetSource(), citation.GetAdvisoryId()); err != nil {
			return err
		}
		if err := instant(field+".modified", citation.GetModified(), true); err != nil {
			return err
		}
		if citation.GetNormalization() == 0 {
			return &event.Violation{Field: field + ".normalization", Reason: "is unspecified"}
		}
	}
	return nil
}

func rating(rated *vulnerabilityv1.Rating) error {
	if rated == nil {
		return nil
	}
	severity := rated.GetSeverity()
	if err := declared("rating.severity.type", int32(severity.GetType()), vulnerabilityv1.Severity_Type_name, true); err != nil {
		return err
	}
	if err := text("rating.severity.score", severity.GetScore(), vulnerability.MaxScoreLength, true); err != nil {
		return err
	}
	if err := text("rating.severity.assessed_by", severity.GetAssessedBy(), vulnerability.MaxAssessorLength, false); err != nil {
		return err
	}
	if err := advisoryName("rating", rated.GetSource(), rated.GetAdvisoryId()); err != nil {
		return err
	}
	if rated.GetPolicy() == 0 {
		return &event.Violation{Field: "rating.policy", Reason: "is unspecified"}
	}
	return nil
}

func advisoryName(field, source, id string) error {
	if err := text(field+".source", source, vulnerability.MaxSourceLength, true); err != nil {
		return err
	}
	if !vulnerability.Identifier(id) {
		return &event.Violation{Field: field + ".advisory_id", Reason: "is missing or malformed"}
	}
	return nil
}

// A finding names the record that last named its item; an assessment, which
// may be about an asset that has reported nothing assessable, only when.
func inventoryBasis(basis *vulnerabilityv1.InventoryBasis, named bool) error {
	if basis == nil {
		return &event.Violation{Field: "inventory", Reason: "is missing"}
	}
	if err := text("inventory.record_id", basis.GetRecordId(), inventory.MaxRecordIDLength, named); err != nil {
		return err
	}
	if err := instant("inventory.last_seen", basis.GetLastSeen(), named); err != nil {
		return err
	}
	if err := text("inventory.scan_record_id", basis.GetScanRecordId(), inventory.MaxRecordIDLength, false); err != nil {
		return err
	}
	if err := instant("inventory.scanned_at", basis.GetScannedAt(), false); err != nil {
		return err
	}
	return instant("inventory.as_of", basis.GetAsOf(), true)
}

func intelligenceBasis(basis *vulnerabilityv1.IntelligenceBasis, named bool) error {
	if basis == nil {
		return &event.Violation{Field: "intelligence", Reason: "is missing"}
	}
	if err := text("intelligence.source", basis.GetSource(), vulnerability.MaxSourceLength, named); err != nil {
		return err
	}
	if err := text("intelligence.feed", basis.GetFeed(), vulnerability.MaxFeedLength, named); err != nil {
		return err
	}
	if err := instant("intelligence.synced_at", basis.GetSyncedAt(), false); err != nil {
		return err
	}
	return instant("intelligence.as_of", basis.GetAsOf(), true)
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
	if at := value.AsTime(); at.Before(vulnerability.EarliestInstant) || at.After(vulnerability.LatestInstant) {
		return &event.Violation{Field: field, Reason: "is outside the instants the platform can hold"}
	}
	return nil
}

func declared(field string, value int32, known map[int32]string, required bool) error {
	if value == 0 {
		if required {
			return &event.Violation{Field: field, Reason: "is unspecified"}
		}
		return nil
	}
	if _, declared := known[value]; !declared {
		return &event.Violation{Field: field, Reason: "is not a value the contract declares"}
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
