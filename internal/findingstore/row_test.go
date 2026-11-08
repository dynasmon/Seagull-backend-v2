package findingstore

import (
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

var decidedAt = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)

func TestAFindingIsStoredUnderItsEpisodeWithTheRecordItCameIn(t *testing.T) {
	made := fixtures.Decision{AgentID: "web-01", DecidedAt: decidedAt, OpenedAt: decidedAt.Add(-48 * time.Hour)}.Finding()
	published, err := proto.Marshal(&vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Finding{Finding: made}})
	if err != nil {
		t.Fatalf("encode the finding: %v", err)
	}

	row := ProjectFinding(made, published)
	want := FindingRow{
		TenantID:        "default",
		AgentID:         "web-01",
		ItemID:          made.GetItemId(),
		VulnerabilityID: "CVE-2024-6119",
		OpenedAt:        decidedAt.Add(-48 * time.Hour),
		State:           "affected",

		InventoryAsOf:    decidedAt.Add(-time.Hour),
		IntelligenceAsOf: decidedAt.Add(-2 * time.Hour),
		DecidedAt:        decidedAt,

		PackageName:      "libssl3",
		PackageVersion:   "3.0.11-1~deb12u2",
		AdvisedEcosystem: "Debian:12",
		AdvisedPackage:   "openssl",
		Fix:              "3.0.14-1~deb12u2",
		SeverityType:     "cvss_v3",
		SeverityScore:    made.GetRating().GetSeverity().GetScore(),
	}
	if string(row.Record) != string(published) {
		t.Fatal("the stored record is not the one the matcher published")
	}
	row.Record = nil
	if !reflect.DeepEqual(row, want) {
		t.Fatalf("the finding is stored as\n%+v\nwant\n%+v", row, want)
	}
}

func TestWhatAFindingLeavesOutIsStoredAsAbsent(t *testing.T) {
	made := fixtures.Decision{DecidedAt: decidedAt}.Finding()
	made.State = vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS
	made.Unassessable = vulnerabilityv1.Unassessable_UNASSESSABLE_UNREADABLE_ADVISORY
	made.OpenedAt, made.Rating, made.Fix = nil, nil, ""

	row := ProjectFinding(made, nil)
	if row.State != "cannot_assess" || row.Unassessable != "unreadable_advisory" {
		t.Errorf("a finding that could not be assessed is stored as %q because %q", row.State, row.Unassessable)
	}
	if !row.OpenedAt.Equal(epoch) || row.SeverityType != "" || row.SeverityScore != "" || row.Fix != "" {
		t.Errorf("what was never given is stored as opened %s, rated %q %q, fixed by %q", row.OpenedAt, row.SeverityType, row.SeverityScore, row.Fix)
	}
}

func TestAnAssessmentIsStoredWithWhatItCouldNotAssessCounted(t *testing.T) {
	record := fixtures.Decision{AgentID: "web-01", DecidedAt: decidedAt}.Assessment(4, 1)
	assessed := record.GetAssessment()
	assessed.Stale = true
	assessed.Unassessed = append(assessed.Unassessed, &vulnerabilityv1.Assessment_Unassessed{
		Reason: vulnerabilityv1.Unassessable_UNASSESSABLE_UNVERSIONED_PACKAGE, Packages: 3,
	})

	row := ProjectAssessment(assessed, []byte("published"))
	want := AssessmentRow{
		TenantID:         "default",
		AgentID:          "web-01",
		Scope:            "asset",
		InventoryAsOf:    decidedAt.Add(-time.Hour),
		IntelligenceAsOf: decidedAt.Add(-2 * time.Hour),
		DecidedAt:        decidedAt,
		Stale:            true,
		Open:             4,
		Closed:           1,
		Unassessed:       5,
	}
	if string(row.Record) != "published" {
		t.Fatal("the stored record is not the one the matcher published")
	}
	row.Record = nil
	if !reflect.DeepEqual(row, want) {
		t.Fatalf("the assessment is stored as\n%+v\nwant\n%+v", row, want)
	}
}
