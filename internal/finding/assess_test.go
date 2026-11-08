package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

var (
	scanned   = time.Date(2026, time.November, 8, 6, 0, 0, 0, time.UTC)
	fetched   = time.Date(2026, time.November, 8, 5, 0, 0, 0, time.UTC)
	synced    = time.Date(2026, time.November, 8, 4, 0, 0, 0, time.UTC)
	evaluated = time.Date(2026, time.November, 8, 6, 30, 0, 0, time.UTC)
	fresh     = Policy{Freshness: 48 * time.Hour}
)

func itemNamed(name string) string {
	digest := sha256.Sum256([]byte(name))
	return hex.EncodeToString(digest[:])
}

func held(name, version, source string) Item {
	return Item{
		ID:       itemNamed(name),
		Package:  &inventoryv1.Package{Name: name, Version: version, Architecture: "amd64", Manager: "dpkg", Source: source},
		RecordID: "inv-0000000001",
		LastSeen: scanned,
	}
}

func debianHost(items ...Item) Asset {
	return Asset{
		TenantID: "acme",
		AgentID:  "web-01",
		System:   &inventoryv1.OperatingSystem{Platform: "debian", Version: "12.5"},
		Packages: items,
		Scan:     Scan{RecordID: "inv-0000000001", ScannedAt: scanned},
		AsOf:     scanned,
	}
}

func fixedIn(id, version string, cves ...string) Advisory {
	return Advisory{
		Source: "osv", ID: id, Modified: fetched.Add(-time.Hour), Normalization: 1, Upstream: cves,
		Affected: []*vulnerabilityv1.Affected{{
			Ecosystem: "Debian:12", Name: "openssl",
			Ranges: []*vulnerabilityv1.Range{{Type: vulnerabilityv1.Range_TYPE_ECOSYSTEM, Events: []*vulnerabilityv1.Event{
				{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: "0"}},
				{Boundary: &vulnerabilityv1.Event_Fixed{Fixed: version}},
			}}},
		}},
	}
}

func intelligenceOf(advisories ...Advisory) Intelligence {
	return Intelligence{Advisories: advisories, Feed: Feed{Source: "osv", Name: "Debian", SyncedAt: synced}, AsOf: fetched}
}

func decisions(evaluation Evaluation) map[Name]*vulnerabilityv1.Finding {
	made := map[Name]*vulnerabilityv1.Finding{}
	for _, decided := range evaluation.Findings {
		made[Name{ItemID: decided.GetItemId(), VulnerabilityID: decided.GetVulnerabilityId()}] = decided
	}
	return made
}

func only(t *testing.T, evaluation Evaluation) *vulnerabilityv1.Finding {
	t.Helper()
	if len(evaluation.Findings) != 1 {
		t.Fatalf("the evaluation decided %d findings: %v", len(evaluation.Findings), evaluation.Findings)
	}
	return evaluation.Findings[0]
}

func valid(t *testing.T, evaluation Evaluation) {
	t.Helper()
	for _, decided := range evaluation.Findings {
		if err := ValidateRecord(&vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Finding{Finding: decided}}); err != nil {
			t.Errorf("the matcher would publish a finding the writer refuses: %v\n%v", err, decided)
		}
	}
	if err := ValidateRecord(&vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Assessment{Assessment: evaluation.Assessment}}); err != nil {
		t.Errorf("the matcher would publish an assessment the writer refuses: %v\n%v", err, evaluation.Assessment)
	}
}

func previously(state vulnerabilityv1.FindingState, opened time.Time, name, vulnerabilityID string) map[Name]*vulnerabilityv1.Finding {
	decided := &vulnerabilityv1.Finding{
		SchemaVersion: SchemaVersion, TenantId: "acme", AgentId: "web-01",
		ItemId: itemNamed(name), VulnerabilityId: vulnerabilityID, State: state,
		Package:         &inventoryv1.Package{Name: name, Version: "3.0.11-1~deb12u2", Manager: "dpkg", Source: "openssl"},
		Advised:         &vulnerabilityv1.AdvisedPackage{Ecosystem: "Debian:12", Name: "openssl"},
		ComparedVersion: "3.0.11-1~deb12u2",
		Citations:       []*vulnerabilityv1.Citation{{Source: "osv", AdvisoryId: "DSA-5764-1", Modified: timestamppb.New(fetched.Add(-48 * time.Hour)), Normalization: 1}},
		OpenedAt:        timestamppb.New(opened),
		Inventory:       &vulnerabilityv1.InventoryBasis{RecordId: "inv-0000000000", LastSeen: timestamppb.New(opened), AsOf: timestamppb.New(opened)},
		Intelligence:    &vulnerabilityv1.IntelligenceBasis{Source: "osv", Feed: "Debian", AsOf: timestamppb.New(opened)},
		DecidedAt:       timestamppb.New(opened),
	}
	return map[Name]*vulnerabilityv1.Finding{{ItemID: decided.ItemId, VulnerabilityID: vulnerabilityID}: decided}
}

func TestAVersionBeforeTheFixIsAffectedFromTheInventoryItWasFoundIn(t *testing.T) {
	evaluation := Assess(debianHost(held("libssl3", "3.0.11-1~deb12u2+b1", "openssl (3.0.11-1~deb12u2)")),
		intelligenceOf(fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119")), nil, evaluated, fresh)
	valid(t, evaluation)

	decided := only(t, evaluation)
	switch {
	case decided.GetState() != vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED:
		t.Errorf("the finding is %s", decided.GetState())
	case decided.GetVulnerabilityId() != "CVE-2024-6119" || decided.GetItemId() != itemNamed("libssl3"):
		t.Errorf("the finding is named %s on %s", decided.GetVulnerabilityId(), decided.GetItemId())
	case decided.GetComparedVersion() != "3.0.11-1~deb12u2" || decided.GetFix() != "3.0.14-1~deb12u2":
		t.Errorf("the source version %q was compared and %q offered as the fix", decided.GetComparedVersion(), decided.GetFix())
	case !decided.GetOpenedAt().AsTime().Equal(scanned):
		t.Errorf("the finding opened at %s, and the inventory it was found in is of %s", decided.GetOpenedAt().AsTime(), scanned)
	case decided.GetAdvised().GetName() != "openssl" || len(decided.GetCitations()) != 1 || decided.GetCitations()[0].GetAdvisoryId() != "DSA-5764-1":
		t.Errorf("the finding is advised as %v and cites %v", decided.GetAdvised(), decided.GetCitations())
	}
	if assessed := evaluation.Assessment; assessed.GetScope() != vulnerabilityv1.Assessment_SCOPE_ASSET || assessed.GetOpen() != 1 || assessed.GetClosed() != 0 || assessed.GetStale() {
		t.Errorf("the assessment is %v", assessed)
	}
}

func TestAnOpenFindingDecidedAgainKeepsWhenItOpened(t *testing.T) {
	opened := scanned.Add(-72 * time.Hour)
	for _, state := range []vulnerabilityv1.FindingState{vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, vulnerabilityv1.FindingState_FINDING_STATE_REINTRODUCED} {
		evaluation := Assess(debianHost(held("libssl3", "3.0.11-1~deb12u2", "openssl")),
			intelligenceOf(fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119")),
			previously(state, opened, "libssl3", "CVE-2024-6119"), evaluated, fresh)
		valid(t, evaluation)
		if decided := only(t, evaluation); decided.GetState() != state || !decided.GetOpenedAt().AsTime().Equal(opened) {
			t.Errorf("a finding open as %s since %s is decided again as %s since %s", state, opened, decided.GetState(), decided.GetOpenedAt().AsTime())
		}
	}
}

func TestAFixAReintroductionAndARemovalLeaveAHistory(t *testing.T) {
	opened := scanned.Add(-72 * time.Hour)
	intelligence := intelligenceOf(fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119"))

	upgraded := Assess(debianHost(held("libssl3", "3.0.14-1~deb12u2", "openssl")), intelligence,
		previously(vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, opened, "libssl3", "CVE-2024-6119"), evaluated, fresh)
	valid(t, upgraded)
	if fix := only(t, upgraded); fix.GetState() != vulnerabilityv1.FindingState_FINDING_STATE_FIXED || fix.GetFix() != "3.0.14-1~deb12u2" ||
		!fix.GetOpenedAt().AsTime().Equal(opened) || upgraded.Assessment.GetClosed() != 1 {
		t.Errorf("an upgrade past the fix is decided as %v", fix)
	}

	downgraded := Assess(debianHost(held("libssl3", "3.0.11-1~deb12u2", "openssl")), intelligence, decisions(upgraded), evaluated, fresh)
	valid(t, downgraded)
	if back := only(t, downgraded); back.GetState() != vulnerabilityv1.FindingState_FINDING_STATE_REINTRODUCED || !back.GetOpenedAt().AsTime().Equal(scanned) {
		t.Errorf("a fix undone is decided as %s, opened %s", back.GetState(), back.GetOpenedAt().AsTime())
	}

	removed := Assess(debianHost(held("curl", "7.88.1-10+deb12u5", "")), intelligence, decisions(downgraded), evaluated, fresh)
	valid(t, removed)
	if gone := only(t, removed); gone.GetState() != vulnerabilityv1.FindingState_FINDING_STATE_REMOVED || !gone.GetOpenedAt().AsTime().Equal(scanned) ||
		gone.GetItemId() != itemNamed("libssl3") {
		t.Errorf("a package the newest scan no longer names is decided as %v", gone)
	}
}

func TestStaleIntelligenceRaisesWhatItFindsAndClosesNothing(t *testing.T) {
	opened := scanned.Add(-72 * time.Hour)
	intelligence := intelligenceOf(fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119"), fixedIn("DSA-5800-1", "3.0.15-1~deb12u1", "CVE-2024-9143"))
	intelligence.Feed.SyncedAt = scanned.Add(-49 * time.Hour)

	evaluation := Assess(debianHost(held("libssl3", "3.0.14-1~deb12u2", "openssl")), intelligence,
		previously(vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, opened, "libssl3", "CVE-2024-6119"), evaluated, fresh)
	valid(t, evaluation)
	if !evaluation.Assessment.GetStale() || evaluation.Assessment.GetClosed() != 0 {
		t.Fatalf("an assessment on intelligence %s older than its inventory is %v", scanned.Sub(intelligence.Feed.SyncedAt), evaluation.Assessment)
	}
	if raised := only(t, evaluation); raised.GetVulnerabilityId() != "CVE-2024-9143" || raised.GetState() != vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED {
		t.Errorf("stale intelligence decided %v, and it should raise the new CVE and close nothing", raised)
	}
}

func TestAnAssetThePlatformCannotPlaceIsAssessedAsSuchAndItsFindingsStand(t *testing.T) {
	never := intelligenceOf(fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119"))
	never.Feed.SyncedAt = time.Time{}
	for _, case_ := range []struct {
		name         string
		system       *inventoryv1.OperatingSystem
		intelligence Intelligence
		want         vulnerabilityv1.Unassessable
	}{
		{"no operating system yet", nil, intelligenceOf(), vulnerabilityv1.Unassessable_UNASSESSABLE_NO_OPERATING_SYSTEM},
		{"a distribution no feed is read for", &inventoryv1.OperatingSystem{Platform: "arch"}, intelligenceOf(), vulnerabilityv1.Unassessable_UNASSESSABLE_UNKNOWN_DISTRIBUTION},
		{"a release advisories are not scoped to", &inventoryv1.OperatingSystem{Platform: "debian", Codename: "sid"}, intelligenceOf(), vulnerabilityv1.Unassessable_UNASSESSABLE_UNKNOWN_RELEASE},
		{"a feed never read whole", &inventoryv1.OperatingSystem{Platform: "debian", Version: "12"}, never, vulnerabilityv1.Unassessable_UNASSESSABLE_STALE_INTELLIGENCE},
	} {
		asset := debianHost(held("libssl3", "3.0.11-1~deb12u2", "openssl"))
		asset.System = case_.system
		evaluation := Assess(asset, case_.intelligence,
			previously(vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, scanned, "libssl3", "CVE-2024-6119"), evaluated, fresh)
		valid(t, evaluation)
		if len(evaluation.Findings) != 0 || evaluation.Assessment.GetUnassessable() != case_.want {
			t.Errorf("%s: assessed as %s with %d findings", case_.name, evaluation.Assessment.GetUnassessable(), len(evaluation.Findings))
		}
	}
}

func TestAPackageThatCannotBeJudgedIsCountedAndKeepsWhatWasOpen(t *testing.T) {
	unversioned := held("libssl3", "", "openssl")
	foreign := held("requests", "2.31.0", "")
	foreign.Package.Manager = "pip"
	opened := scanned.Add(-72 * time.Hour)

	evaluation := Assess(debianHost(unversioned, foreign), intelligenceOf(fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119")),
		previously(vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, opened, "libssl3", "CVE-2024-6119"), evaluated, fresh)
	valid(t, evaluation)

	kept := only(t, evaluation)
	if kept.GetState() != vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS || kept.GetUnassessable() != vulnerabilityv1.Unassessable_UNASSESSABLE_UNVERSIONED_PACKAGE ||
		!kept.GetOpenedAt().AsTime().Equal(opened) {
		t.Errorf("an open finding on a package that lost its version is decided as %v", kept)
	}
	counted := map[vulnerabilityv1.Unassessable]uint32{}
	for _, entry := range evaluation.Assessment.GetUnassessed() {
		counted[entry.GetReason()] = entry.GetPackages()
	}
	if counted[vulnerabilityv1.Unassessable_UNASSESSABLE_UNVERSIONED_PACKAGE] != 1 || counted[vulnerabilityv1.Unassessable_UNASSESSABLE_FOREIGN_MANAGER] != 1 || len(counted) != 2 {
		t.Errorf("the assessment counts %v", counted)
	}
}

func TestOneCVEToldByThreeAdvisoriesIsOneFindingJudgedByAllOfThem(t *testing.T) {
	dsa := fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119")
	record := fixedIn("DEBIAN-CVE-2024-6119", "3.0.14-1~deb12u2", "CVE-2024-6119")
	dla := fixedIn("DLA-3942-1", "3.0.15-1~deb12u1", "CVE-2024-6119")
	dla.Upstream, dla.Aliases = nil, []string{"CVE-2024-6119"}

	evaluation := Assess(debianHost(held("libssl3", "3.0.14-1~deb12u2", "openssl")), intelligenceOf(dsa, record, dla), nil, evaluated, fresh)
	valid(t, evaluation)
	decided := only(t, evaluation)
	if decided.GetState() != vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED || decided.GetFix() != "3.0.15-1~deb12u1" || len(decided.GetCitations()) != 3 {
		t.Errorf("a version two advisories call fixed and one affected is decided as %s with fix %q citing %v",
			decided.GetState(), decided.GetFix(), decided.GetCitations())
	}

	unnamed := fixedIn("DSA-9999-1", "3.0.14-1~deb12u2")
	if decided := only(t, Assess(debianHost(held("libssl3", "3.0.11-1~deb12u2", "openssl")), intelligenceOf(unnamed), nil, evaluated, fresh)); decided.GetVulnerabilityId() != "DSA-9999-1" {
		t.Errorf("an advisory naming no CVE is a finding named %q", decided.GetVulnerabilityId())
	}
}

func TestWhatAnAdvisoryCannotSayIsCannotAssessAndAWithdrawnOneClosesItsFinding(t *testing.T) {
	unreadable := fixedIn("DSA-5764-1", "3.0.14~~!!", "CVE-2024-6119")
	evaluation := Assess(debianHost(held("libssl3", "3.0.11-1~deb12u2", "openssl")), intelligenceOf(unreadable), nil, evaluated, fresh)
	valid(t, evaluation)
	if decided := only(t, evaluation); decided.GetState() != vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS ||
		decided.GetUnassessable() != vulnerabilityv1.Unassessable_UNASSESSABLE_UNREADABLE_ADVISORY || decided.GetOpenedAt() != nil {
		t.Errorf("a boundary nobody can order is decided as %v", decided)
	}

	opened := scanned.Add(-72 * time.Hour)
	closedBy := Assess(debianHost(held("libssl3", "3.0.11-1~deb12u2", "openssl")), intelligenceOf(),
		previously(vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, opened, "libssl3", "CVE-2024-6119"), evaluated, fresh)
	valid(t, closedBy)
	if decided := only(t, closedBy); decided.GetState() != vulnerabilityv1.FindingState_FINDING_STATE_NOT_AFFECTED || !decided.GetOpenedAt().AsTime().Equal(opened) {
		t.Errorf("a finding no advisory tells any more is decided as %v", decided)
	}
}

func TestAPartialAssessmentJudgesOnlyThePackagesAnAdvisoryNames(t *testing.T) {
	curl := held("curl", "7.88.1-10+deb12u5", "")
	previous := previously(vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, scanned, "curl", "CVE-2023-38545")
	previous[Name{ItemID: itemNamed("curl"), VulnerabilityID: "CVE-2023-38545"}].Advised.Name = "curl"

	evaluation := AssessPackages(debianHost(held("libssl3", "3.0.11-1~deb12u2", "openssl"), curl),
		intelligenceOf(fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119")), previous, []string{"openssl"}, evaluated, fresh)
	valid(t, evaluation)
	if decided := only(t, evaluation); decided.GetItemId() != itemNamed("libssl3") {
		t.Errorf("an advisory about openssl decided %v", decided)
	}
	if evaluation.Assessment.GetScope() != vulnerabilityv1.Assessment_SCOPE_PACKAGES {
		t.Errorf("the assessment covered %s", evaluation.Assessment.GetScope())
	}
}

func TestTheRatingShownIsTheMostSpecificOneAnAdvisoryAsserted(t *testing.T) {
	rated := func(kind vulnerabilityv1.Severity_Type, score, by string) *vulnerabilityv1.Severity {
		return &vulnerabilityv1.Severity{Type: kind, Score: score, AssessedBy: by}
	}
	v2 := rated(vulnerabilityv1.Severity_TYPE_CVSS_V2, "AV:N/AC:L/Au:N/C:P/I:N/A:N", "")
	v3 := rated(vulnerabilityv1.Severity_TYPE_CVSS_V3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "")
	nvd := rated(vulnerabilityv1.Severity_TYPE_CVSS_V3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "NVD")
	ubuntu := rated(vulnerabilityv1.Severity_TYPE_UBUNTU, "medium", "")

	for _, case_ := range []struct {
		name       string
		advisory   []*vulnerabilityv1.Severity
		entry      []*vulnerabilityv1.Severity
		want       *vulnerabilityv1.Severity
		perPackage bool
	}{
		{"a rating of this package before one of the whole advisory", []*vulnerabilityv1.Severity{v3}, []*vulnerabilityv1.Severity{v2}, v2, true},
		{"the database's own before another assessor's", []*vulnerabilityv1.Severity{nvd, v2}, nil, v2, false},
		{"the distribution's scale before cvss", []*vulnerabilityv1.Severity{v3, ubuntu}, nil, ubuntu, false},
		{"a newer cvss before an older one", []*vulnerabilityv1.Severity{v2, v3}, nil, v3, false},
	} {
		advisory := fixedIn("USN-7000-1", "3.0.14-1~deb12u2", "CVE-2024-6119")
		advisory.Severities = case_.advisory
		advisory.Affected[0].Severities = case_.entry
		decided := only(t, Assess(debianHost(held("libssl3", "3.0.11-1~deb12u2", "openssl")), intelligenceOf(advisory), nil, evaluated, fresh))
		rating := decided.GetRating()
		if !proto.Equal(rating.GetSeverity(), case_.want) || rating.GetPackageSpecific() != case_.perPackage || rating.GetPolicy() != RatingPolicy ||
			rating.GetAdvisoryId() != "USN-7000-1" {
			t.Errorf("%s: shown %v", case_.name, rating)
		}
	}
	if decided := only(t, Assess(debianHost(held("libssl3", "3.0.11-1~deb12u2", "openssl")), intelligenceOf(fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119")), nil, evaluated, fresh)); decided.GetRating() != nil {
		t.Errorf("a vulnerability nobody rated is shown as %v", decided.GetRating())
	}
}

// A replay evaluates against what it decided the first time, so labelling has
// to be a fixed point: the same inventory and intelligence decide the same
// findings under the same names whether or not they were decided before.
func TestDecidingAgainFromTheSameInventoryAndIntelligenceDecidesTheSame(t *testing.T) {
	opened := scanned.Add(-72 * time.Hour)
	asset := debianHost(held("libssl3", "3.0.11-1~deb12u2", "openssl"), held("curl", "7.88.1-10+deb12u5", ""))
	intelligence := intelligenceOf(fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119"), fixedIn("DSA-5800-1", "3.0.15-1~deb12u1", "CVE-2024-9143"))
	previous := previously(vulnerabilityv1.FindingState_FINDING_STATE_FIXED, opened, "libssl3", "CVE-2024-6119")

	first := Assess(asset, intelligence, previous, evaluated, fresh)
	again := Assess(asset, intelligence, decisions(first), evaluated, fresh)
	valid(t, first)
	if len(first.Findings) != len(again.Findings) {
		t.Fatalf("deciding again made %d findings, the first time %d", len(again.Findings), len(first.Findings))
	}
	for index := range first.Findings {
		if !proto.Equal(first.Findings[index], again.Findings[index]) {
			t.Errorf("deciding again changed\n%v\ninto\n%v", first.Findings[index], again.Findings[index])
		}
	}
}

func TestAnInstalledVersionNoManagerWouldWriteIsCountedAndNeverJudged(t *testing.T) {
	evaluation := Assess(debianHost(held("libssl3", "3.0.11 1", "openssl")), intelligenceOf(fixedIn("DSA-5764-1", "3.0.14-1~deb12u2", "CVE-2024-6119")), nil, evaluated, fresh)
	valid(t, evaluation)
	if len(evaluation.Findings) != 0 {
		t.Fatalf("a version dpkg refuses was judged into %v", evaluation.Findings)
	}
	if unassessed := evaluation.Assessment.GetUnassessed(); len(unassessed) != 1 ||
		unassessed[0].GetReason() != vulnerabilityv1.Unassessable_UNASSESSABLE_UNREADABLE_VERSION || unassessed[0].GetPackages() != 1 {
		t.Fatalf("the assessment counts %v", unassessed)
	}
}
