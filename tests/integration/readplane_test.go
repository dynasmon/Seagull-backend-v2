//go:build integration

package integration_test

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	"github.com/dynasmon/Seagull-backend-v2/internal/matching"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

func readPlane(t *testing.T, address string) *hunt.Lister {
	t.Helper()

	reader := migratedHunter(t, address)
	built, err := hunt.NewLister(hunt.ListerOptions{
		Inventory:       reader,
		Vulnerabilities: reader,
		Compiler:        huntCompiler(t),
		Metrics:         hunt.NewMetrics(metrics.New("readplane")),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("build the read plane: %v", err)
	}
	return built
}

func granted(t *testing.T, tenants ...string) hunt.Scope {
	t.Helper()
	scope, err := hunt.NewScope(tenants)
	if err != nil {
		t.Fatalf("scope %v: %v", tenants, err)
	}
	return scope
}

func listContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// Every item of a kind an asset holds, page after page, as the read plane
// lists them: what an asset currently has, asked of the production reader.
func listedItems(t *testing.T, address, owner, agent string, kind inventoryv1.Kind) ([]*inventoryv1.HeldItem, *inventoryv1.Scan) {
	t.Helper()

	plane := readPlane(t, address)
	asked := &inventoryv1.ItemQuery{AgentId: agent, Kind: kind, Limit: 2}
	var (
		items []*inventoryv1.HeldItem
		scan  *inventoryv1.Scan
	)
	for range 1000 {
		page, err := plane.Items(listContext(t), granted(t, owner), asked)
		if err != nil {
			t.Fatalf("list the %s of %s: %v", kind, agent, err)
		}
		items, scan = append(items, page.GetItems()...), page.GetScan()
		if page.GetNextCursor() == "" {
			return items, scan
		}
		asked.Cursor = page.GetNextCursor()
	}
	t.Fatal("the listing never ended")
	return nil, nil
}

func current(t *testing.T, address, owner, agent string) map[string]string {
	t.Helper()
	items, _ := listedItems(t, address, owner, agent, inventoryv1.Kind_KIND_PACKAGE)
	versions := map[string]string{}
	for _, item := range items {
		versions[item.GetItem().GetPackage().GetName()] = item.GetItem().GetPackage().GetVersion()
	}
	return versions
}

func instances(t *testing.T, address, owner, agent string, kind inventoryv1.Kind) []string {
	t.Helper()
	items, _ := listedItems(t, address, owner, agent, kind)
	var listed []string
	for _, item := range items {
		if account := item.GetItem().GetUser(); account != nil {
			listed = append(listed, account.GetName()+" "+account.GetUid())
			continue
		}
		listed = append(listed, item.GetItem().GetPackage().GetName()+" "+item.GetItem().GetPackage().GetVersion())
	}
	slices.Sort(listed)
	return listed
}

func TestAnOperatorListsTheInstalledPackagesOfAnAssetAndSeesHowOldTheListIs(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: at, Packages: []fixtures.Installed{
		{Name: "openssl", Version: "3.0.13", Architecture: "amd64", Manager: "dpkg"},
		{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"},
	}})

	items, scan := listedItems(t, address, owner, "web-01", inventoryv1.Kind_KIND_PACKAGE)
	if len(items) != 2 || items[0].GetItem().GetPackage().GetName() != "curl" || items[1].GetItem().GetPackage().GetName() != "openssl" {
		t.Fatalf("the asset lists %v", items)
	}
	for _, item := range items {
		if !item.GetCurrent() || item.GetKind() != inventoryv1.Kind_KIND_PACKAGE || !item.GetLastSeen().AsTime().Equal(at) || item.GetItem().GetPackage().GetManager() != "dpkg" {
			t.Errorf("an installed package is listed as %v", item)
		}
	}
	if !scan.GetScannedAt().AsTime().Equal(at) || scan.GetItems() != 2 || scan.GetKind() != inventoryv1.Kind_KIND_PACKAGE {
		t.Errorf("the list is said to be as old as %v", scan)
	}
}

// Only a full enumeration says what is gone, so what a delta named of a kind
// nobody enumerated is current, for the read plane as for the matcher.
func TestWhatADeltaNamedOfAKindNeverEnumeratedInFullIsCurrent(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC),
		Mode: inventoryv1.Mode_MODE_DELTA, Packages: []fixtures.Installed{{Name: "jq", Version: "1.7", Architecture: "amd64", Manager: "dpkg"}}})

	items, scan := listedItems(t, address, owner, "web-01", inventoryv1.Kind_KIND_PACKAGE)
	if len(items) != 1 || !items[0].GetCurrent() || scan != nil {
		t.Fatalf("a package a delta named is listed as %v, under the scan %v", items, scan)
	}
	asset, found, err := matchingReaderOf(t, address).Asset(listContext(t), matching.Asset{TenantID: owner, AgentID: "web-01"})
	if err != nil || !found || len(asset.Packages) != 1 {
		t.Fatalf("the matcher reads %d packages (%v, %v) where the read plane lists one", len(asset.Packages), found, err)
	}
}

func TestAVersionADeltaRepeatsIsListedOnce(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC)
	openssl := fixtures.Installed{Name: "openssl-libs", Version: "1:3.5.1-3.el9", Architecture: "x86_64", Manager: "rpm"}

	fold(t, store, owner, fixtures.PackageScan{AgentID: "rocky-01", At: at, Packages: []fixtures.Installed{openssl}})
	fold(t, store, owner, fixtures.PackageScan{AgentID: "rocky-01", At: at.Add(time.Hour), Mode: inventoryv1.Mode_MODE_DELTA, Packages: []fixtures.Installed{openssl}})

	if rows := storedRows(t, inspector(t, address), owner, "package_name = 'openssl-libs'"); rows != 2 {
		t.Fatalf("the fixture stores %d rows, so it proves nothing about listing one", rows)
	}
	items, _ := listedItems(t, address, owner, "rocky-01", inventoryv1.Kind_KIND_PACKAGE)
	if len(items) != 1 || !items[0].GetLastSeen().AsTime().Equal(at.Add(time.Hour)) {
		t.Fatalf("one instance said by two rows is listed as %v", items)
	}
}

func TestAPackagesHistoryListsEveryInstanceOfItsNameNewestFirst(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "rocky-01", At: at, Packages: kernels(olderKernel)})
	fold(t, store, owner, fixtures.PackageScan{AgentID: "rocky-01", At: at.Add(time.Hour), Packages: kernels(olderKernel, newerKernel)})
	fold(t, store, owner, fixtures.PackageScan{AgentID: "rocky-01", At: at.Add(2 * time.Hour), Packages: kernels(newerKernel)})

	plane := readPlane(t, address)
	want := []string{newerKernel + " held 11:00AM", olderKernel + " gone 10:00AM"}
	for _, limit := range []uint32{0, 1} {
		asked := &inventoryv1.ItemQuery{AgentId: "rocky-01", Kind: inventoryv1.Kind_KIND_PACKAGE, Name: "kernel-core", Limit: limit}
		var read []string
		for range 10 {
			page, err := plane.Items(listContext(t), granted(t, owner), asked)
			if err != nil {
				t.Fatalf("read the history of kernel-core: %v", err)
			}
			for _, item := range page.GetItems() {
				state := "gone"
				if item.GetCurrent() {
					state = "held"
				}
				read = append(read, item.GetItem().GetPackage().GetVersion()+" "+state+" "+item.GetLastSeen().AsTime().Format(time.Kitchen))
			}
			if page.GetNextCursor() == "" {
				break
			}
			asked.Cursor = page.GetNextCursor()
		}
		if !slices.Equal(read, want) {
			t.Fatalf("the history of kernel-core read %d at a time is %q, want %q", limit, read, want)
		}
	}
}

func TestAnItemListingIsReadPageByPageAndEnds(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	var installed []fixtures.Installed
	for _, name := range []string{"bash", "curl", "dash", "gzip", "tar"} {
		installed = append(installed, fixtures.Installed{Name: name, Version: "1.0", Architecture: "amd64", Manager: "dpkg"})
	}
	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC), Packages: installed})

	if listed := instances(t, address, owner, "web-01", inventoryv1.Kind_KIND_PACKAGE); !slices.Equal(listed, []string{"bash 1.0", "curl 1.0", "dash 1.0", "gzip 1.0", "tar 1.0"}) {
		t.Fatalf("five packages read two at a time are %q", listed)
	}
}

func TestAnAssetIsListedWithItsEnumerationsItsHostAndWhenAnythingOnItWasLastSeen(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC)

	foldRecord(t, store, owner, systemScan("web-01", at))
	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", Hostname: "web-01.acme.example", At: at.Add(time.Hour), Packages: []fixtures.Installed{
		{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"},
	}})
	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-02", At: at, Packages: []fixtures.Installed{}})

	page, err := readPlane(t, address).Assets(listContext(t), granted(t, owner), &inventoryv1.AssetQuery{})
	if err != nil {
		t.Fatalf("list the assets: %v", err)
	}
	if len(page.GetAssets()) != 2 || page.GetAssets()[0].GetAgentId() != "web-01" || page.GetAssets()[1].GetAgentId() != "web-02" {
		t.Fatalf("the tenant lists %v", page.GetAssets())
	}
	first := page.GetAssets()[0]
	if len(first.GetScans()) != 2 || first.GetScans()[0].GetKind() != inventoryv1.Kind_KIND_OPERATING_SYSTEM ||
		!first.GetScans()[1].GetScannedAt().AsTime().Equal(at.Add(time.Hour)) || first.GetScans()[1].GetItems() != 1 {
		t.Errorf("web-01 is listed with the enumerations %v", first.GetScans())
	}
	if first.GetHost().GetHostname() != "web-01.acme.example" || !first.GetLastSeen().AsTime().Equal(at.Add(time.Hour)) || first.GetTenantId() != owner {
		t.Errorf("web-01 is listed on host %v, last seen %v", first.GetHost(), first.GetLastSeen().AsTime())
	}
	if second := page.GetAssets()[1]; len(second.GetScans()) != 1 || second.GetScans()[0].GetItems() != 0 || !second.GetLastSeen().AsTime().Equal(at) {
		t.Errorf("an asset that enumerated no package is listed as %v", second)
	}
}

func TestAStaleInventoryIsFoundByTheOldestEnumerationItHolds(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	now := time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: now.Add(-10 * 24 * time.Hour), Packages: []fixtures.Installed{}})
	foldRecord(t, store, owner, systemScan("web-01", now))
	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-02", At: now, Packages: []fixtures.Installed{}})

	page, err := readPlane(t, address).Assets(listContext(t), granted(t, owner), &inventoryv1.AssetQuery{ScannedBefore: timestamppb.New(now.Add(-48 * time.Hour))})
	if err != nil {
		t.Fatalf("list the stale assets: %v", err)
	}
	if len(page.GetAssets()) != 1 || page.GetAssets()[0].GetAgentId() != "web-01" {
		t.Fatalf("the assets with a kind enumerated more than two days ago are %v", page.GetAssets())
	}
}

func TestAnotherTenantsAssetIsNeitherListedNorRead(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	mine, theirs := tenant(t), tenant(t)
	at := time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC)
	fold(t, store, mine, fixtures.PackageScan{AgentID: "web-01", At: at, Packages: []fixtures.Installed{{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"}}})
	fold(t, store, theirs, fixtures.PackageScan{AgentID: "web-09", At: at, Packages: []fixtures.Installed{{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"}}})

	plane := readPlane(t, address)
	page, err := plane.Assets(listContext(t), granted(t, mine), &inventoryv1.AssetQuery{AgentIds: []string{"web-01", "web-09"}})
	if err != nil || len(page.GetAssets()) != 1 || page.GetAssets()[0].GetAgentId() != "web-01" {
		t.Fatalf("a caller of one tenant lists %v (%v)", page.GetAssets(), err)
	}
	items, err := plane.Items(listContext(t), granted(t, mine), &inventoryv1.ItemQuery{AgentId: "web-09", Kind: inventoryv1.Kind_KIND_PACKAGE})
	if err != nil || len(items.GetItems()) != 0 || items.GetScan() != nil {
		t.Fatalf("a caller of one tenant read another's asset: %v (%v)", items, err)
	}
}

func TestAssetsAreListedPageByPage(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC)
	for _, agent := range []string{"web-03", "web-01", "web-02"} {
		fold(t, store, owner, fixtures.PackageScan{AgentID: agent, At: at, Packages: []fixtures.Installed{}})
	}

	plane := readPlane(t, address)
	asked := &inventoryv1.AssetQuery{Limit: 2}
	var listed []string
	for range 10 {
		page, err := plane.Assets(listContext(t), granted(t, owner), asked)
		if err != nil {
			t.Fatalf("list the assets: %v", err)
		}
		for _, asset := range page.GetAssets() {
			listed = append(listed, asset.GetAgentId())
		}
		if page.GetNextCursor() == "" {
			break
		}
		asked.Cursor = page.GetNextCursor()
	}
	if !slices.Equal(listed, []string{"web-01", "web-02", "web-03"}) {
		t.Fatalf("three assets read two at a time are %v", listed)
	}
}

func TestFindingsAreListedByAssetAndByCVEWithinTheCallersTenantsOnly(t *testing.T) {
	address := storeAddress(t)
	store := migratedFindingStore(t, address)
	mine, theirs := tenant(t), tenant(t)
	at := time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC)
	keepFindings(t, store,
		fixtures.Decision{TenantID: mine, AgentID: "web-01", Vulnerability: "CVE-2024-6119", DecidedAt: at}.Record(),
		fixtures.Decision{TenantID: mine, AgentID: "web-01", Vulnerability: "CVE-2024-6387", Item: "openssh-server", DecidedAt: at}.Record(),
		fixtures.Decision{TenantID: mine, AgentID: "web-02", Vulnerability: "CVE-2024-6387", Item: "openssh-server", DecidedAt: at}.Record(),
		fixtures.Decision{TenantID: theirs, AgentID: "web-09", Vulnerability: "CVE-2024-6387", Item: "openssh-server", DecidedAt: at}.Record(),
	)

	plane := readPlane(t, address)
	named := func(asked *vulnerabilityv1.FindingQuery) []string {
		t.Helper()
		page, err := plane.Findings(listContext(t), granted(t, mine), asked)
		if err != nil {
			t.Fatalf("list the findings: %v", err)
		}
		var read []string
		for _, decided := range page.GetFindings() {
			read = append(read, decided.GetAgentId()+" "+decided.GetVulnerabilityId())
		}
		slices.Sort(read)
		return read
	}
	if byAsset := named(&vulnerabilityv1.FindingQuery{AgentIds: []string{"web-01"}}); !slices.Equal(byAsset, []string{"web-01 CVE-2024-6119", "web-01 CVE-2024-6387"}) {
		t.Errorf("the findings of web-01 are %q", byAsset)
	}
	if byCVE := named(&vulnerabilityv1.FindingQuery{VulnerabilityIds: []string{"CVE-2024-6387"}}); !slices.Equal(byCVE, []string{"web-01 CVE-2024-6387", "web-02 CVE-2024-6387"}) {
		t.Errorf("the findings of CVE-2024-6387 are %q", byCVE)
	}
	if byPackage := named(&vulnerabilityv1.FindingQuery{PackageNames: []string{"openssh-server"}, AgentIds: []string{"web-09", "web-02"}}); !slices.Equal(byPackage, []string{"web-02 CVE-2024-6387"}) {
		t.Errorf("the findings on openssh-server of web-02 and another tenant's web-09 are %q", byPackage)
	}
}

func TestAFindingIsListedAsItsNewestDecisionAndByWhereItStands(t *testing.T) {
	address := storeAddress(t)
	store := migratedFindingStore(t, address)
	owner := tenant(t)
	day := time.Date(2026, time.November, 18, 6, 0, 0, 0, time.UTC)
	keepFindings(t, store,
		fixtures.Decision{TenantID: owner, AgentID: "web-01", DecidedAt: day}.Record(),
		fixtures.Decision{TenantID: owner, AgentID: "web-01", State: vulnerabilityv1.FindingState_FINDING_STATE_FIXED, OpenedAt: day.Add(-time.Hour), DecidedAt: day.Add(24 * time.Hour)}.Record(),
	)

	plane := readPlane(t, address)
	page, err := plane.Findings(listContext(t), granted(t, owner), &vulnerabilityv1.FindingQuery{})
	if err != nil || len(page.GetFindings()) != 1 || page.GetFindings()[0].GetState() != vulnerabilityv1.FindingState_FINDING_STATE_FIXED {
		t.Fatalf("a fixed finding is listed as %v (%v)", page.GetFindings(), err)
	}
	open, err := plane.Findings(listContext(t), granted(t, owner), &vulnerabilityv1.FindingQuery{States: []vulnerabilityv1.FindingState{vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED}})
	if err != nil || len(open.GetFindings()) != 0 {
		t.Fatalf("a fixed finding is listed among the affected: %v (%v)", open.GetFindings(), err)
	}
}

// ADR 49: a whole assessment of an asset on fresh intelligence decides every
// open finding again, so an open decision older than the newest one is a
// finding it did not list and is not open; a stale one is not held to.
func TestAnOpenFindingTheNewestWholeAssessmentDidNotListIsNotListed(t *testing.T) {
	address := storeAddress(t)
	store := migratedFindingStore(t, address)
	owner := tenant(t)
	day := time.Date(2026, time.November, 18, 6, 0, 0, 0, time.UTC)

	first := fixtures.Decision{TenantID: owner, AgentID: "web-01", Vulnerability: "CVE-2024-6119", DecidedAt: day}
	second := fixtures.Decision{TenantID: owner, AgentID: "web-01", Vulnerability: "CVE-2024-6387", Item: "openssh-server", DecidedAt: day.Add(24 * time.Hour)}
	stale := fixtures.Decision{TenantID: owner, AgentID: "web-01", DecidedAt: day.Add(48 * time.Hour)}.Assessment(0, 0)
	stale.GetAssessment().Stale = true
	keepFindings(t, store, first.Record(), first.Assessment(1, 0), second.Record(), second.Assessment(1, 0), stale)

	page, err := readPlane(t, address).Findings(listContext(t), granted(t, owner), &vulnerabilityv1.FindingQuery{})
	if err != nil {
		t.Fatalf("list the findings: %v", err)
	}
	if len(page.GetFindings()) != 1 || page.GetFindings()[0].GetVulnerabilityId() != "CVE-2024-6387" {
		t.Fatalf("the asset lists %v, and its newest whole assessment found CVE-2024-6387 alone", page.GetFindings())
	}
}

func TestAFindingsHistoryListsEveryEpisodeNewestFirstPageByPage(t *testing.T) {
	address := storeAddress(t)
	store := migratedFindingStore(t, address)
	owner := tenant(t)
	day := time.Date(2026, time.November, 1, 6, 0, 0, 0, time.UTC)
	reopened := day.Add(3 * 24 * time.Hour)
	decided := func(state vulnerabilityv1.FindingState, opened time.Time, days int) *vulnerabilityv1.FindingRecord {
		return fixtures.Decision{TenantID: owner, AgentID: "web-01", State: state, OpenedAt: opened, DecidedAt: day.Add(time.Duration(days) * 24 * time.Hour)}.Record()
	}
	keepFindings(t, store,
		decided(vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, day, 0),
		decided(vulnerabilityv1.FindingState_FINDING_STATE_FIXED, day, 2),
		decided(vulnerabilityv1.FindingState_FINDING_STATE_REINTRODUCED, reopened, 3),
	)
	named := fixtures.Decision{TenantID: owner, AgentID: "web-01"}.Finding()

	plane := readPlane(t, address)
	asked := &vulnerabilityv1.FindingHistoryQuery{AgentId: "web-01", ItemId: named.GetItemId(), VulnerabilityId: named.GetVulnerabilityId(), Limit: 1}
	var states []string
	for range 10 {
		page, err := plane.History(listContext(t), granted(t, owner), asked)
		if err != nil {
			t.Fatalf("read the history: %v", err)
		}
		for _, decision := range page.GetFindings() {
			states = append(states, decision.GetState().String())
		}
		if page.GetNextCursor() == "" {
			break
		}
		asked.Cursor = page.GetNextCursor()
	}
	want := []string{"FINDING_STATE_REINTRODUCED", "FINDING_STATE_FIXED", "FINDING_STATE_AFFECTED"}
	if !slices.Equal(states, want) {
		t.Fatalf("the history reads %q, want %q", states, want)
	}
}

// How each asset was last assessed whole, stale or not: it says why a finding
// may not have been decided again.
func TestTheNewestWholeAssessmentOfEachAssetIsListed(t *testing.T) {
	address := storeAddress(t)
	store := migratedFindingStore(t, address)
	owner := tenant(t)
	day := time.Date(2026, time.November, 18, 6, 0, 0, 0, time.UTC)

	partial := fixtures.Decision{TenantID: owner, AgentID: "web-01", DecidedAt: day.Add(72 * time.Hour)}.Assessment(1, 0)
	partial.GetAssessment().Scope = vulnerabilityv1.Assessment_SCOPE_PACKAGES
	newest := fixtures.Decision{TenantID: owner, AgentID: "web-01", DecidedAt: day.Add(48 * time.Hour)}.Assessment(2, 0)
	newest.GetAssessment().Stale = true
	keepFindings(t, store,
		fixtures.Decision{TenantID: owner, AgentID: "web-01", DecidedAt: day}.Assessment(1, 0), newest, partial,
		fixtures.Decision{TenantID: owner, AgentID: "web-02", DecidedAt: day}.Assessment(0, 0),
	)

	page, err := readPlane(t, address).Assessments(listContext(t), granted(t, owner), &vulnerabilityv1.AssessmentQuery{})
	if err != nil {
		t.Fatalf("list the assessments: %v", err)
	}
	if len(page.GetAssessments()) != 2 || !proto.Equal(page.GetAssessments()[0], newest.GetAssessment()) || page.GetAssessments()[1].GetAgentId() != "web-02" {
		t.Fatalf("the assets were last assessed as %v", page.GetAssessments())
	}
}

func TestEveryVersionOfAnAdvisoryIsReadBackNewestFirst(t *testing.T) {
	address := storeAddress(t)
	store := migratedAdvisoryStore(t, address)
	id := "DSA-" + owned(t)
	modified := time.Date(2026, time.November, 10, 6, 0, 0, 0, time.UTC)
	older, newer := version(id, "openssl", modified, 1, "3.0.13-1"), version(id, "openssl", modified.Add(time.Hour), 1, "3.0.14-1")
	hold(t, store, advised(older), advised(newer))

	page, err := readPlane(t, address).Advisories(listContext(t), granted(t, "default"), &vulnerabilityv1.AdvisoryQuery{
		Question: &vulnerabilityv1.AdvisoryQuery_Advisory{Advisory: &vulnerabilityv1.AdvisoryName{Source: "osv", Id: id}},
	})
	if err != nil {
		t.Fatalf("read the advisory: %v", err)
	}
	if len(page.GetAdvisories()) != 2 || !proto.Equal(page.GetAdvisories()[0], newer) || !proto.Equal(page.GetAdvisories()[1], older) {
		t.Fatalf("the versions of %s read back as %v", id, page.GetAdvisories())
	}
}

func TestTheAdvisoriesNamingAPackageAreReadAtTheirNewestVersion(t *testing.T) {
	address := storeAddress(t)
	store := migratedAdvisoryStore(t, address)
	pkg := "libfoo-" + owned(t)
	modified := time.Date(2026, time.November, 10, 6, 0, 0, 0, time.UTC)
	kept, dropped := "DSA-1-"+pkg, "DSA-2-"+pkg
	hold(t, store,
		advised(version(kept, pkg, modified, 1, "1.0-1")), advised(version(kept, pkg, modified.Add(time.Hour), 1, "1.1-1")),
		advised(version(dropped, pkg, modified, 1, "1.0-1")), advised(version(dropped, pkg, modified.Add(time.Hour), 1)),
	)

	page, err := readPlane(t, address).Advisories(listContext(t), granted(t, "default"), &vulnerabilityv1.AdvisoryQuery{
		Question: &vulnerabilityv1.AdvisoryQuery_Package{Package: &vulnerabilityv1.AdvisedPackage{Ecosystem: "Debian:12", Name: pkg}},
	})
	if err != nil {
		t.Fatalf("read the advisories of %s: %v", pkg, err)
	}
	if len(page.GetAdvisories()) != 1 || page.GetAdvisories()[0].GetId() != kept || !page.GetAdvisories()[0].GetModified().AsTime().Equal(modified.Add(time.Hour)) {
		t.Fatalf("the advisories naming %s are %v", pkg, page.GetAdvisories())
	}
}

func TestAWithdrawnAdvisoryIsLeftOutUnlessAskedFor(t *testing.T) {
	address := storeAddress(t)
	store := migratedAdvisoryStore(t, address)
	id := "DSA-" + owned(t)
	modified := time.Date(2026, time.November, 10, 6, 0, 0, 0, time.UTC)
	withdrawal := version(id, "openssl", modified.Add(time.Hour), 1, "3.0.13-1")
	withdrawal.Withdrawn = timestamppb.New(modified.Add(time.Hour))
	hold(t, store, advised(version(id, "openssl", modified, 1, "3.0.13-1")), advised(withdrawal))

	plane := readPlane(t, address)
	for asked, want := range map[bool]int{false: 0, true: 2} {
		page, err := plane.Advisories(listContext(t), granted(t, "default"), &vulnerabilityv1.AdvisoryQuery{
			Question:  &vulnerabilityv1.AdvisoryQuery_Advisory{Advisory: &vulnerabilityv1.AdvisoryName{Source: "osv", Id: id}},
			Withdrawn: asked,
		})
		if err != nil || len(page.GetAdvisories()) != want {
			t.Errorf("asking withdrawn=%v read %d versions of a withdrawn advisory (%v), want %d", asked, len(page.GetAdvisories()), err, want)
		}
	}
}
