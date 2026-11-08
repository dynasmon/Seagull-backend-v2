package finding

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

var decidedAt = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)

func stamp(offset time.Duration) *timestamppb.Timestamp {
	return timestamppb.New(decidedAt.Add(offset))
}

func decided() *vulnerabilityv1.Finding {
	return &vulnerabilityv1.Finding{
		SchemaVersion:   SchemaVersion,
		TenantId:        "acme",
		AgentId:         "web-01",
		ItemId:          strings.Repeat("ab", ItemIDLength/2),
		VulnerabilityId: "CVE-2024-6119",
		State:           vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED,
		Package: &inventoryv1.Package{
			Name: "libssl3", Version: "3.0.11-1~deb12u2", Architecture: "amd64", Manager: "dpkg", Source: "openssl",
		},
		Advised:         &vulnerabilityv1.AdvisedPackage{Ecosystem: "Debian:12", Name: "openssl"},
		ComparedVersion: "3.0.11-1~deb12u2",
		Fix:             "3.0.14-1~deb12u2",
		Citations: []*vulnerabilityv1.Citation{
			{Source: "osv-debian", AdvisoryId: "DSA-5764-1", Modified: stamp(-48 * time.Hour), Normalization: 1},
			{Source: "osv-debian", AdvisoryId: "DEBIAN-CVE-2024-6119", Modified: stamp(-24 * time.Hour), Normalization: 1},
		},
		Rating: &vulnerabilityv1.Rating{
			Severity: &vulnerabilityv1.Severity{Type: vulnerabilityv1.Severity_TYPE_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
			Source:   "osv-debian", AdvisoryId: "DEBIAN-CVE-2024-6119", Policy: 1,
		},
		OpenedAt: stamp(-time.Hour),
		Inventory: &vulnerabilityv1.InventoryBasis{
			RecordId: "inv-0000000001", LastSeen: stamp(-2 * time.Hour),
			ScanRecordId: "inv-0000000001", ScannedAt: stamp(-2 * time.Hour), AsOf: stamp(-2 * time.Hour),
		},
		Intelligence: &vulnerabilityv1.IntelligenceBasis{
			Source: "osv-debian", Feed: "Debian", SyncedAt: stamp(-3 * time.Hour), AsOf: stamp(-3 * time.Hour),
		},
		DecidedAt: stamp(0),
	}
}

func assessed() *vulnerabilityv1.Assessment {
	return &vulnerabilityv1.Assessment{
		SchemaVersion: SchemaVersion,
		TenantId:      "acme",
		AgentId:       "web-01",
		Scope:         vulnerabilityv1.Assessment_SCOPE_ASSET,
		Inventory:     &vulnerabilityv1.InventoryBasis{RecordId: "inv-0000000001", AsOf: stamp(-2 * time.Hour)},
		Intelligence:  &vulnerabilityv1.IntelligenceBasis{Source: "osv-debian", Feed: "Debian", AsOf: stamp(-3 * time.Hour)},
		Open:          3,
		Closed:        1,
		Unassessed: []*vulnerabilityv1.Assessment_Unassessed{
			{Reason: vulnerabilityv1.Unassessable_UNASSESSABLE_FOREIGN_MANAGER, Packages: 12},
		},
		DecidedAt: stamp(0),
	}
}

func refusedAt(t *testing.T, err error) string {
	t.Helper()
	var violation *event.Violation
	if !errors.As(err, &violation) {
		t.Fatalf("refused with %v, which names no field", err)
	}
	return violation.Field
}

func TestAFindingTheMatcherMakesIsAdmitted(t *testing.T) {
	for name, made := range map[string]func() *vulnerabilityv1.Finding{
		"affected": decided,
		"cannot assess and never open": func() *vulnerabilityv1.Finding {
			unread := decided()
			unread.State = vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS
			unread.Unassessable = vulnerabilityv1.Unassessable_UNASSESSABLE_UNREADABLE_ADVISORY
			unread.OpenedAt, unread.Fix, unread.Rating = nil, "", nil
			return unread
		},
		"removed": func() *vulnerabilityv1.Finding {
			gone := decided()
			gone.State = vulnerabilityv1.FindingState_FINDING_STATE_REMOVED
			gone.Citations = nil
			return gone
		},
		"on an asset that never sent a snapshot": func() *vulnerabilityv1.Finding {
			unscanned := decided()
			unscanned.Inventory.ScanRecordId, unscanned.Inventory.ScannedAt = "", nil
			unscanned.Intelligence.SyncedAt = nil
			return unscanned
		},
	} {
		record := &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Finding{Finding: made()}}
		if err := ValidateRecord(record); err != nil {
			t.Errorf("%s: refused with %v", name, err)
		}
	}

	record := &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Assessment{Assessment: assessed()}}
	if err := ValidateRecord(record); err != nil {
		t.Errorf("an assessment was refused with %v", err)
	}
}

func TestAFindingIsRefusedAtTheFieldItGetsWrong(t *testing.T) {
	for _, case_ := range []struct {
		name   string
		mutate func(*vulnerabilityv1.Finding)
		field  string
	}{
		{"a schema from the future", func(f *vulnerabilityv1.Finding) { f.SchemaVersion = MaxSchemaVersion + 1 }, "schema_version"},
		{"no tenant", func(f *vulnerabilityv1.Finding) { f.TenantId = "" }, "tenant_id"},
		{"an agent identifier the registry would refuse", func(f *vulnerabilityv1.Finding) { f.AgentId = "web 01" }, "agent_id"},
		{"an item named by its package", func(f *vulnerabilityv1.Finding) { f.ItemId = "libssl3" }, "item_id"},
		{"an item in capitals", func(f *vulnerabilityv1.Finding) { f.ItemId = strings.Repeat("AB", ItemIDLength/2) }, "item_id"},
		{"no vulnerability", func(f *vulnerabilityv1.Finding) { f.VulnerabilityId = "" }, "vulnerability_id"},
		{"a vulnerability spelled with a space", func(f *vulnerabilityv1.Finding) { f.VulnerabilityId = "CVE 2024 6119" }, "vulnerability_id"},
		{"no state", func(f *vulnerabilityv1.Finding) { f.State = vulnerabilityv1.FindingState_FINDING_STATE_UNSPECIFIED }, "state"},
		{"a state from the future", func(f *vulnerabilityv1.Finding) { f.State = 99 }, "state"},
		{"a reason for an assessed finding", func(f *vulnerabilityv1.Finding) {
			f.Unassessable = vulnerabilityv1.Unassessable_UNASSESSABLE_UNREADABLE_ADVISORY
		}, "unassessable"},
		{"no reason it could not be assessed", func(f *vulnerabilityv1.Finding) {
			f.State = vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS
		}, "unassessable"},
		{"a closing that names no episode", func(f *vulnerabilityv1.Finding) {
			f.State, f.OpenedAt = vulnerabilityv1.FindingState_FINDING_STATE_FIXED, nil
		}, "opened_at"},
		{"no package", func(f *vulnerabilityv1.Finding) { f.Package = nil }, "package"},
		{"an unnamed package", func(f *vulnerabilityv1.Finding) { f.Package.Name = "" }, "package.name"},
		{"an unversioned package", func(f *vulnerabilityv1.Finding) { f.Package.Version = "" }, "package.version"},
		{"a package no manager installed", func(f *vulnerabilityv1.Finding) { f.Package.Manager = "" }, "package.manager"},
		{"a source longer than the inventory holds", func(f *vulnerabilityv1.Finding) {
			f.Package.Source = strings.Repeat("s", inventory.MaxSourceLength+1)
		}, "package.source"},
		{"an ecosystem as a feed spells it", func(f *vulnerabilityv1.Finding) { f.Advised.Ecosystem = "Ubuntu:22.04" }, "advised.ecosystem"},
		{"no advised package", func(f *vulnerabilityv1.Finding) { f.Advised.Name = "" }, "advised.name"},
		{"no compared version", func(f *vulnerabilityv1.Finding) { f.ComparedVersion = "" }, "compared_version"},
		{"a fix longer than a version", func(f *vulnerabilityv1.Finding) {
			f.Fix = strings.Repeat("1", vulnerability.MaxVersionLength+1)
		}, "fix"},
		{"too many citations", func(f *vulnerabilityv1.Finding) {
			for len(f.Citations) <= MaxCitations {
				f.Citations = append(f.Citations, f.Citations[0])
			}
		}, "citations"},
		{"a citation of no advisory", func(f *vulnerabilityv1.Finding) { f.Citations[1].AdvisoryId = "" }, "citations[1].advisory_id"},
		{"a citation of no version", func(f *vulnerabilityv1.Finding) { f.Citations[0].Modified = nil }, "citations[0].modified"},
		{"a citation read by no rules", func(f *vulnerabilityv1.Finding) { f.Citations[0].Normalization = 0 }, "citations[0].normalization"},
		{"a rating of no kind", func(f *vulnerabilityv1.Finding) { f.Rating.Severity.Type = 0 }, "rating.severity.type"},
		{"a rating with no score", func(f *vulnerabilityv1.Finding) { f.Rating.Severity.Score = "" }, "rating.severity.score"},
		{"a rating no policy chose", func(f *vulnerabilityv1.Finding) { f.Rating.Policy = 0 }, "rating.policy"},
		{"no inventory", func(f *vulnerabilityv1.Finding) { f.Inventory = nil }, "inventory"},
		{"no record naming the item", func(f *vulnerabilityv1.Finding) { f.Inventory.RecordId = "" }, "inventory.record_id"},
		{"no inventory instant", func(f *vulnerabilityv1.Finding) { f.Inventory.AsOf = nil }, "inventory.as_of"},
		{"no intelligence", func(f *vulnerabilityv1.Finding) { f.Intelligence = nil }, "intelligence"},
		{"no feed", func(f *vulnerabilityv1.Finding) { f.Intelligence.Feed = "" }, "intelligence.feed"},
		{"no intelligence instant", func(f *vulnerabilityv1.Finding) { f.Intelligence.AsOf = nil }, "intelligence.as_of"},
		{"an instant the store cannot hold", func(f *vulnerabilityv1.Finding) {
			f.Intelligence.SyncedAt = timestamppb.New(time.Date(1800, time.January, 1, 0, 0, 0, 0, time.UTC))
		}, "intelligence.synced_at"},
		{"no decision instant", func(f *vulnerabilityv1.Finding) { f.DecidedAt = nil }, "decided_at"},
	} {
		made := decided()
		case_.mutate(made)
		record := &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Finding{Finding: made}}
		if got := refusedAt(t, ValidateRecord(record)); got != case_.field {
			t.Errorf("%s: refused at %q, want %q", case_.name, got, case_.field)
		}
	}
}

func TestAnAssessmentIsRefusedAtTheFieldItGetsWrong(t *testing.T) {
	for _, case_ := range []struct {
		name   string
		mutate func(*vulnerabilityv1.Assessment)
		field  string
	}{
		{"no scope", func(a *vulnerabilityv1.Assessment) { a.Scope = 0 }, "scope"},
		{"a reason from the future", func(a *vulnerabilityv1.Assessment) { a.Unassessable = 99 }, "unassessable"},
		{"a reason counted twice", func(a *vulnerabilityv1.Assessment) { a.Unassessed = append(a.Unassessed, a.Unassessed[0]) }, "unassessed[1].reason"},
		{"a reason counting nothing", func(a *vulnerabilityv1.Assessment) { a.Unassessed[0].Packages = 0 }, "unassessed[0].packages"},
		{"no inventory instant", func(a *vulnerabilityv1.Assessment) { a.Inventory.AsOf = nil }, "inventory.as_of"},
		{"no intelligence", func(a *vulnerabilityv1.Assessment) { a.Intelligence = nil }, "intelligence"},
		{"no decision instant", func(a *vulnerabilityv1.Assessment) { a.DecidedAt = nil }, "decided_at"},
	} {
		made := assessed()
		case_.mutate(made)
		record := &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Assessment{Assessment: made}}
		if got := refusedAt(t, ValidateRecord(record)); got != case_.field {
			t.Errorf("%s: refused at %q, want %q", case_.name, got, case_.field)
		}
	}

	if got := refusedAt(t, ValidateRecord(&vulnerabilityv1.FindingRecord{})); got != "record" {
		t.Errorf("an empty record was refused at %q", got)
	}
}

// The ceiling is not reached by any field the contract bounds, so a finding
// the platform made always fits the topic that carries it; what it refuses is
// a record padded with fields this build does not know.
func TestTheWidestFindingFitsItsCeilingAndAPaddedOneDoesNot(t *testing.T) {
	widest := decided()
	widest.TenantId = strings.Repeat("t", event.MaxTenantIDLength)
	widest.AgentId = "a" + strings.Repeat("b", 63)
	widest.VulnerabilityId = "V" + strings.Repeat("1", vulnerability.MaxIDLength-1)
	widest.Package = &inventoryv1.Package{
		Name:         strings.Repeat("n", inventory.MaxNameLength),
		Version:      strings.Repeat("1", inventory.MaxVersionLength),
		Architecture: strings.Repeat("a", inventory.MaxArchitectureLength),
		Manager:      strings.Repeat("m", inventory.MaxManagerLength),
		Source:       strings.Repeat("s", inventory.MaxSourceLength),
		Vendor:       strings.Repeat("v", inventory.MaxVendorLength),
		SizeBytes:    ^uint64(0),
		InstalledAt:  stamp(-time.Hour),
	}
	widest.Advised.Name = strings.Repeat("p", vulnerability.MaxPackageLength)
	widest.ComparedVersion = strings.Repeat("1", vulnerability.MaxVersionLength)
	widest.Fix = strings.Repeat("2", vulnerability.MaxVersionLength)
	widest.Citations = nil
	for range MaxCitations {
		widest.Citations = append(widest.Citations, &vulnerabilityv1.Citation{
			Source:        strings.Repeat("s", vulnerability.MaxSourceLength),
			AdvisoryId:    "A" + strings.Repeat("1", vulnerability.MaxIDLength-1),
			Modified:      stamp(-time.Hour),
			Normalization: ^uint32(0),
		})
	}
	widest.Rating.Severity.Score = strings.Repeat("s", vulnerability.MaxScoreLength)
	widest.Rating.Severity.AssessedBy = strings.Repeat("a", vulnerability.MaxAssessorLength)
	widest.Rating.Source = strings.Repeat("s", vulnerability.MaxSourceLength)
	widest.Rating.AdvisoryId = "A" + strings.Repeat("1", vulnerability.MaxIDLength-1)
	widest.Rating.Policy = ^uint32(0)
	widest.Inventory.RecordId = strings.Repeat("r", inventory.MaxRecordIDLength)
	widest.Inventory.ScanRecordId = strings.Repeat("r", inventory.MaxRecordIDLength)
	widest.Intelligence.Source = strings.Repeat("s", vulnerability.MaxSourceLength)
	widest.Intelligence.Feed = strings.Repeat("f", vulnerability.MaxFeedLength)

	record := &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Finding{Finding: widest}}
	if err := ValidateRecord(record); err != nil {
		t.Fatalf("the widest finding, %d bytes, was refused: %v", proto.Size(record), err)
	}

	unknown := protowire.AppendTag(nil, 15, protowire.BytesType)
	record.ProtoReflect().SetUnknown(protowire.AppendBytes(unknown, make([]byte, MaxRecordBytes-proto.Size(record))))
	if got := refusedAt(t, ValidateRecord(record)); got != "record" {
		t.Fatalf("a record of %d bytes was refused at %q, want the record itself", proto.Size(record), got)
	}
}
