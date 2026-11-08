//go:build integration

package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/finding"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/matching"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

func matchingReaderOf(t *testing.T, address string) *clickhouse.MatchingReader {
	t.Helper()
	migratedFindingStore(t, address)
	reader, err := clickhouse.NewMatchingReader(storeSettings(address))
	if err != nil {
		t.Fatalf("build the matching reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := reader.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass the reader's verification: %v", err)
	}
	return reader
}

func systemScan(agentID string, at time.Time) *inventoryv1.Record {
	return &inventoryv1.Record{
		RecordId:      "inv-system-01",
		SchemaVersion: inventory.SchemaVersion,
		Kind:          inventoryv1.Kind_KIND_OPERATING_SYSTEM,
		Mode:          inventoryv1.Mode_MODE_SNAPSHOT,
		CollectedAt:   timestamppb.New(at),
		Origin:        &eventv1.Origin{AgentId: agentID, TenantId: "default"},
		Collection:    &eventv1.Collection{Collector: "syscollector", Source: "os-release"},
		Items: []*inventoryv1.Item{{Body: &inventoryv1.Item_OperatingSystem{OperatingSystem: &inventoryv1.OperatingSystem{
			Name: "AlmaLinux", Version: "9.4", Platform: "almalinux", Family: "rhel",
		}}}},
	}
}

func TestTheMatcherReadsAnAssetAsTheNewestScanLeftIt(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	reader := matchingReaderOf(t, address)
	owner, agentID := tenant(t), agentIdentifier(t)

	first := time.Date(2026, time.November, 1, 6, 0, 0, 0, time.UTC)
	later := first.Add(24 * time.Hour)
	foldRecord(t, store, owner, systemScan(agentID, first))
	fold(t, store, owner, fixtures.PackageScan{RecordID: "inv-packages-01", AgentID: agentID, At: first, Packages: []fixtures.Installed{
		{Name: "openssl-libs", Version: "1:3.0.7-27.el9", Architecture: "x86_64", Manager: "rpm", Source: "openssl-3.0.7-27.el9.src.rpm", InstalledAt: first.Add(-time.Hour)},
		{Name: "curl", Version: "7.76.1-29.el9", Architecture: "x86_64", Manager: "rpm"},
	}})
	fold(t, store, owner, fixtures.PackageScan{RecordID: "inv-packages-02", AgentID: agentID, At: later, Packages: []fixtures.Installed{
		{Name: "openssl-libs", Version: "1:3.0.7-28.el9", Architecture: "x86_64", Manager: "rpm", Source: "openssl-3.0.7-28.el9.src.rpm"},
	}})

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	held, found, err := reader.Asset(ctx, matching.Asset{TenantID: owner, AgentID: agentID})
	if err != nil || !found {
		t.Fatalf("the asset was read as found %t: %v", found, err)
	}
	if held.System.GetPlatform() != "almalinux" || held.System.GetVersion() != "9.4" {
		t.Errorf("the asset runs %v", held.System)
	}
	if len(held.Packages) != 1 || held.Packages[0].Package.GetVersion() != "1:3.0.7-28.el9" || held.Packages[0].RecordID != "inv-packages-02" {
		t.Errorf("the asset holds %v, and the newest scan named openssl-libs alone at -28", held.Packages)
	}
	if held.Scan.RecordID != "inv-packages-02" || !held.Scan.ScannedAt.Equal(later) || !held.AsOf.Equal(later) {
		t.Errorf("the asset was scanned by %s at %s and observed as of %s", held.Scan.RecordID, held.Scan.ScannedAt, held.AsOf)
	}
	if _, found, err := reader.Asset(ctx, matching.Asset{TenantID: owner, AgentID: "nobody-01"}); found || err != nil {
		t.Errorf("an asset nothing was stored for was found: %t, %v", found, err)
	}

	holders, err := reader.Holders(ctx, []string{"openssl-libs", "curl"})
	if err != nil {
		t.Fatalf("read the holders: %v", err)
	}
	var mine []matching.Asset
	for _, holder := range holders {
		if holder.TenantID == owner {
			mine = append(mine, holder)
		}
	}
	if len(mine) != 1 || mine[0].AgentID != agentID {
		t.Errorf("the holders of openssl-libs and curl within the tenant are %v", mine)
	}
}

func almaAdvisory(id, pkg string, modified time.Time, normalization uint32, fixed string) *vulnerabilityv1.Advisory {
	return &vulnerabilityv1.Advisory{
		SchemaVersion: 1,
		Source:        "osv",
		Id:            id,
		Modified:      timestamppb.New(modified),
		Aliases:       []string{"CVE-2026-1111"},
		Upstream:      []string{"CVE-2026-2222"},
		Severities:    []*vulnerabilityv1.Severity{{Type: vulnerabilityv1.Severity_TYPE_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		Provenance: &vulnerabilityv1.Provenance{
			Feed: "AlmaLinux", FeedVersion: `"generation-1"`, Location: "https://osv.example/AlmaLinux/" + id + ".json",
			FetchedAt: timestamppb.New(modified.Add(time.Minute)), Digest: strings.Repeat("cd", 32), Format: "osv 1.9.0", Normalization: normalization,
		},
		Affected: []*vulnerabilityv1.Affected{{
			Ecosystem: "AlmaLinux:9", Name: pkg,
			Ranges: []*vulnerabilityv1.Range{
				{Type: vulnerabilityv1.Range_TYPE_ECOSYSTEM, Events: []*vulnerabilityv1.Event{
					{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: "0"}},
					{Boundary: &vulnerabilityv1.Event_Fixed{Fixed: fixed}},
				}},
				{Type: vulnerabilityv1.Range_TYPE_ECOSYSTEM, Events: []*vulnerabilityv1.Event{
					{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: "2:1.0-1.el9"}},
					{Boundary: &vulnerabilityv1.Event_LastAffected{LastAffected: "2:1.0-5.el9"}},
				}},
			},
			Versions:   []string{"1:3.0.7-24.el9"},
			Severities: []*vulnerabilityv1.Severity{{Type: vulnerabilityv1.Severity_TYPE_CVSS_V2, Score: "AV:N/AC:L/Au:N/C:P/I:N/A:N", AssessedBy: "NVD"}},
		}},
	}
}

// What the matcher judges with has to be what the importer read: the newest
// version of each advisory, its entries rebuilt range by range and event by
// event from the columns they were stored in.
func TestTheMatcherReadsTheNewestVersionOfEachAdvisoryAsItWasRead(t *testing.T) {
	address := storeAddress(t)
	advisories := migratedAdvisoryStore(t, address)
	reader := matchingReaderOf(t, address)
	pkg := "openssl-libs-" + owned(t)
	now := time.Now().UTC().Truncate(time.Millisecond)

	within := now.Truncate(time.Second).Add(-2 * time.Hour)
	first := almaAdvisory("ALSA-"+owned(t), pkg, within.Add(100*time.Millisecond), 1, "1:3.0.7-27.el9")
	second := proto.Clone(first).(*vulnerabilityv1.Advisory)
	second.Modified = timestamppb.New(within.Add(400 * time.Millisecond))
	second.Provenance.FetchedAt = timestamppb.New(now.Add(-90 * time.Minute))
	second.Affected[0].Ranges[0].Events[1] = &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_Fixed{Fixed: "1:3.0.7-28.el9"}}
	withdrawn := almaAdvisory("ALSA-W-"+owned(t), pkg, now.Add(-2*time.Hour), 1, "1:3.0.7-30.el9")
	withdrawn.Withdrawn = timestamppb.New(now.Add(-2 * time.Hour))
	synced, behind := now.Add(-time.Hour), now.Add(-5*time.Hour)
	syncOf := func(source string, at time.Time) *vulnerabilityv1.Record {
		return &vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Sync{Sync: &vulnerabilityv1.FeedSync{
			Source: source, Feed: "AlmaLinux", CheckedAt: timestamppb.New(now), Outcome: vulnerabilityv1.FeedSync_OUTCOME_COMPLETE,
			SyncedAt: timestamppb.New(at),
		}}}
	}
	hold(t, advisories, advised(first), advised(second), advised(withdrawn), syncOf("osv", synced), syncOf("osv-mirror", behind))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	intelligence, err := reader.Read(ctx, "AlmaLinux:9", []string{pkg})
	if err != nil {
		t.Fatalf("read the intelligence: %v", err)
	}
	if intelligence.Feed.Name != "AlmaLinux" || intelligence.Feed.Source != "osv-mirror" || !intelligence.Feed.SyncedAt.Equal(behind) {
		t.Errorf("the feed reads as %+v, and the stalest of its two sources last synced at %s", intelligence.Feed, behind)
	}
	if !intelligence.AsOf.Equal(now.Add(-90 * time.Minute)) {
		t.Errorf("the intelligence is as of %s, and the newest advisory was fetched at %s", intelligence.AsOf, now.Add(-90*time.Minute))
	}
	if len(intelligence.Advisories) != 1 {
		t.Fatalf("read %d advisories, want the newest version of the one not withdrawn", len(intelligence.Advisories))
	}
	read := intelligence.Advisories[0]
	if read.ID != first.Id || !read.Modified.Equal(second.Modified.AsTime()) || read.Normalization != 1 {
		t.Errorf("read %s as of %s", read.ID, read.Modified)
	}
	if !equalNames(read.Aliases, first.Aliases) || !equalNames(read.Upstream, first.Upstream) || len(read.Severities) != 1 ||
		!proto.Equal(read.Severities[0], first.Severities[0]) {
		t.Errorf("read the names %v %v and severities %v", read.Aliases, read.Upstream, read.Severities)
	}
	if len(read.Affected) != 1 || !proto.Equal(read.Affected[0], second.Affected[0]) {
		t.Errorf("read the entry\n%v\nwant\n%v", read.Affected, second.Affected[0])
	}

	before, err := reader.Before(ctx, "osv", first.Id, second.Modified.AsTime(), 1)
	if err != nil || len(before) != 1 || before[0] != (matching.Key{Ecosystem: "AlmaLinux:9", Package: pkg}) {
		t.Errorf("the version before the newest named %v (%v)", before, err)
	}
	if none, err := reader.Before(ctx, "osv", first.Id, first.Modified.AsTime(), 1); err != nil || len(none) != 0 {
		t.Errorf("the first version had a version before it naming %v (%v)", none, err)
	}
}

func equalNames(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

func TestTheMatcherReadsTheNewestDecisionOfEveryFindingOfAnAsset(t *testing.T) {
	address := storeAddress(t)
	store := migratedFindingStore(t, address)
	reader := matchingReaderOf(t, address)
	owner, agentID := tenant(t), agentIdentifier(t)

	day := time.Date(2026, time.November, 1, 6, 0, 0, 0, time.UTC)
	decided := func(vulnerabilityID string, state vulnerabilityv1.FindingState, days int) *vulnerabilityv1.FindingRecord {
		return fixtures.Decision{
			TenantID: owner, AgentID: agentID, Vulnerability: vulnerabilityID, State: state, OpenedAt: day,
			InventoryAsOf: day.Add(time.Duration(days) * 24 * time.Hour), IntelligenceAsOf: day.Add(time.Duration(days)*24*time.Hour - time.Hour),
			DecidedAt: day.Add(time.Duration(days)*24*time.Hour + time.Minute),
		}.Record()
	}
	keepFindings(t, store,
		decided("CVE-2024-6119", vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, 0),
		decided("CVE-2024-6119", vulnerabilityv1.FindingState_FINDING_STATE_FIXED, 1),
		decided("CVE-2024-9143", vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, 0),
		decided("CVE-2024-9143", vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, 2),
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	newest, err := reader.Decisions(ctx, matching.Asset{TenantID: owner, AgentID: agentID})
	if err != nil {
		t.Fatalf("read the decisions: %v", err)
	}
	states := map[string]vulnerabilityv1.FindingState{}
	for name, made := range newest {
		states[name.VulnerabilityID] = made.GetState()
		if name.ItemID != made.GetItemId() {
			t.Errorf("a decision about %s is named by %s", made.GetItemId(), name.ItemID)
		}
	}
	if len(states) != 2 || states["CVE-2024-6119"] != vulnerabilityv1.FindingState_FINDING_STATE_FIXED ||
		states["CVE-2024-9143"] != vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED {
		t.Errorf("the newest decisions are %v", states)
	}
	if latest := newest[finding.Name{ItemID: newest[firstName(newest)].GetItemId(), VulnerabilityID: "CVE-2024-9143"}]; !latest.GetDecidedAt().AsTime().Equal(day.Add(48*time.Hour + time.Minute)) {
		t.Errorf("the open finding decided again reads as decided at %s", latest.GetDecidedAt().AsTime())
	}
}

func firstName(decided map[finding.Name]*vulnerabilityv1.Finding) finding.Name {
	for name := range decided {
		return name
	}
	return finding.Name{}
}
