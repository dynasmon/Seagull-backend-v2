package fixtures

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/finding"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// What the matcher decides of one vulnerability in a Debian host's openssl:
// open since OpenedAt, decided from inventory observed at InventoryAsOf and
// intelligence fetched at IntelligenceAsOf.
type Decision struct {
	TenantID         string
	AgentID          string
	Item             string
	Vulnerability    string
	State            vulnerabilityv1.FindingState
	Version          string
	OpenedAt         time.Time
	InventoryAsOf    time.Time
	IntelligenceAsOf time.Time
	DecidedAt        time.Time
}

func (d Decision) Finding() *vulnerabilityv1.Finding {
	if d.TenantID == "" {
		d.TenantID = "default"
	}
	if d.AgentID == "" {
		d.AgentID = "dev-agent-01"
	}
	if d.Item == "" {
		d.Item = "libssl3"
	}
	if d.Vulnerability == "" {
		d.Vulnerability = "CVE-2024-6119"
	}
	if d.State == vulnerabilityv1.FindingState_FINDING_STATE_UNSPECIFIED {
		d.State = vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED
	}
	if d.Version == "" {
		d.Version = "3.0.11-1~deb12u2"
	}
	if d.DecidedAt.IsZero() {
		d.DecidedAt = time.Now().UTC().Truncate(time.Millisecond)
	}
	if d.InventoryAsOf.IsZero() {
		d.InventoryAsOf = d.DecidedAt.Add(-time.Hour)
	}
	if d.IntelligenceAsOf.IsZero() {
		d.IntelligenceAsOf = d.DecidedAt.Add(-2 * time.Hour)
	}
	if d.OpenedAt.IsZero() {
		d.OpenedAt = d.InventoryAsOf
	}
	item := sha256.Sum256([]byte(d.Item))

	return &vulnerabilityv1.Finding{
		SchemaVersion:   finding.SchemaVersion,
		TenantId:        d.TenantID,
		AgentId:         d.AgentID,
		ItemId:          hex.EncodeToString(item[:]),
		VulnerabilityId: d.Vulnerability,
		State:           d.State,
		Package: &inventoryv1.Package{
			Name: d.Item, Version: d.Version, Architecture: "amd64", Manager: "dpkg", Source: "openssl",
		},
		Advised:         &vulnerabilityv1.AdvisedPackage{Ecosystem: "Debian:12", Name: "openssl"},
		ComparedVersion: d.Version,
		Fix:             "3.0.14-1~deb12u2",
		Citations: []*vulnerabilityv1.Citation{
			{Source: "osv", AdvisoryId: "DSA-5764-1", Modified: timestamppb.New(d.IntelligenceAsOf.Add(-time.Hour)), Normalization: 1},
		},
		Rating: &vulnerabilityv1.Rating{
			Severity: &vulnerabilityv1.Severity{Type: vulnerabilityv1.Severity_TYPE_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
			Source:   "osv", AdvisoryId: "DSA-5764-1", Policy: 1,
		},
		OpenedAt: timestamppb.New(d.OpenedAt),
		Inventory: &vulnerabilityv1.InventoryBasis{
			RecordId: "inv-0000000001", LastSeen: timestamppb.New(d.InventoryAsOf),
			ScanRecordId: "inv-0000000001", ScannedAt: timestamppb.New(d.InventoryAsOf), AsOf: timestamppb.New(d.InventoryAsOf),
		},
		Intelligence: &vulnerabilityv1.IntelligenceBasis{
			Source: "osv", Feed: "Debian", SyncedAt: timestamppb.New(d.IntelligenceAsOf), AsOf: timestamppb.New(d.IntelligenceAsOf),
		},
		DecidedAt: timestamppb.New(d.DecidedAt),
	}
}

func (d Decision) Record() *vulnerabilityv1.FindingRecord {
	return &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Finding{Finding: d.Finding()}}
}

// A whole evaluation of an asset, made at the same instants as the decisions
// it covered.
func (d Decision) Assessment(open, closed uint32) *vulnerabilityv1.FindingRecord {
	decided := d.Finding()
	return &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Assessment{Assessment: &vulnerabilityv1.Assessment{
		SchemaVersion: finding.SchemaVersion,
		TenantId:      decided.GetTenantId(),
		AgentId:       decided.GetAgentId(),
		Scope:         vulnerabilityv1.Assessment_SCOPE_ASSET,
		Inventory:     decided.GetInventory(),
		Intelligence:  decided.GetIntelligence(),
		Open:          open,
		Closed:        closed,
		Unassessed: []*vulnerabilityv1.Assessment_Unassessed{
			{Reason: vulnerabilityv1.Unassessable_UNASSESSABLE_FOREIGN_MANAGER, Packages: 2},
		},
		DecidedAt: decided.GetDecidedAt(),
	}}}
}
