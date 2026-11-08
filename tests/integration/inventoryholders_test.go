//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func holdersOf(t *testing.T, connection driver.Conn, owner, name string) []string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rows, err := connection.Query(ctx, `
		SELECT DISTINCT agent_id FROM asset_package_holders
		WHERE package = ? AND tenant_id = ?
		ORDER BY agent_id`, name, owner)
	if err != nil {
		t.Fatalf("look up the holders of %s: %v", name, err)
	}
	defer func() { _ = rows.Close() }()

	var agents []string
	for rows.Next() {
		var agent string
		if err := rows.Scan(&agent); err != nil {
			t.Fatalf("read a holder of %s: %v", name, err)
		}
		agents = append(agents, agent)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("look up the holders of %s: %v", name, err)
	}
	return agents
}

func TestAnAssetIsFoundByTheNameAnAdvisoryGivesItsPackage(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.November, 8, 10, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{RecordID: "inv-debian", AgentID: "web-01", At: at, Packages: []fixtures.Installed{
		{Name: "libssl3", Version: "3.0.11-1~deb12u2+b1", Architecture: "amd64", Manager: "dpkg", Source: "openssl (3.0.11-1~deb12u2)"},
		{Name: "curl", Version: "7.88.1-10+deb12u5", Architecture: "amd64", Manager: "dpkg"},
	}})
	fold(t, store, owner, fixtures.PackageScan{RecordID: "inv-rocky", AgentID: "db-01", At: at, Packages: []fixtures.Installed{
		{Name: "openssl-libs", Version: "1:3.0.7-27.el9", Architecture: "x86_64", Manager: "rpm", Source: "openssl-3.0.7-27.el9.src.rpm"},
	}})
	fold(t, store, owner, fixtures.PackageScan{RecordID: "inv-python", AgentID: "ci-01", At: at, Packages: []fixtures.Installed{
		{Name: "openssl", Version: "0.1.0", Manager: "pip"},
	}})

	connection := inspector(t, address)
	for name, want := range map[string][]string{
		"openssl":      {"db-01", "web-01"},
		"openssl-libs": {"db-01"},
		"curl":         {"web-01"},
		"libssl3":      nil,
	} {
		if got := holdersOf(t, connection, owner, name); !slices.Equal(got, want) {
			t.Errorf("%s is held by %q, want %q", name, got, want)
		}
	}
}

func TestReplayingAScanLeavesOneHolderPerNameAndALateOneMovesNothing(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	first := time.Date(2026, time.November, 8, 10, 0, 0, 0, time.UTC)
	upgraded := first.Add(24 * time.Hour)

	scan := func(at time.Time, version string) fixtures.PackageScan {
		return fixtures.PackageScan{AgentID: "db-01", At: at, Packages: []fixtures.Installed{
			{Name: "openssl-libs", Version: version, Architecture: "x86_64", Manager: "rpm", Source: "openssl-" + version[2:] + ".src.rpm"},
		}}
	}
	fold(t, store, owner, scan(first, "1:3.0.7-24.el9"))
	fold(t, store, owner, scan(upgraded, "1:3.0.7-27.el9"))
	fold(t, store, owner, scan(upgraded, "1:3.0.7-27.el9"))
	fold(t, store, owner, scan(first, "1:3.0.7-24.el9"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rows, err := inspector(t, address).Query(ctx, `
		SELECT package, last_seen FROM asset_package_holders FINAL
		WHERE tenant_id = ? ORDER BY package`, owner)
	if err != nil {
		t.Fatalf("read the holders: %v", err)
	}
	defer func() { _ = rows.Close() }()

	held := map[string]time.Time{}
	for rows.Next() {
		var name string
		var seen time.Time
		if err := rows.Scan(&name, &seen); err != nil {
			t.Fatalf("read a holder: %v", err)
		}
		if _, twice := held[name]; twice {
			t.Errorf("%s is held twice by one item", name)
		}
		held[name] = seen.UTC()
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read the holders: %v", err)
	}
	if len(held) != 2 || !held["openssl"].Equal(upgraded) || !held["openssl-libs"].Equal(upgraded) {
		t.Fatalf("after an upgrade, a replay and a late scan the holders are %v, want openssl and openssl-libs seen at %s", held, upgraded)
	}
}

type currentPackage struct {
	agent, item, name, source, manager string
}

// The property the table exists for: wherever the store says an asset has a
// package, the lookup finds that asset under every name an advisory could give
// the package, whatever scans came before.
func TestEveryCurrentPackageIsHeldUnderEachNameAnAdvisoryCouldGiveIt(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	random := rand.New(rand.NewPCG(20261108, 1))

	catalogue := []fixtures.Installed{
		{Name: "libssl3", Architecture: "amd64", Manager: "dpkg", Source: "openssl"},
		{Name: "libssl3t64", Architecture: "amd64", Manager: "dpkg", Source: "openssl (3.0.13-0ubuntu3.4)"},
		{Name: "curl", Architecture: "amd64", Manager: "dpkg"},
		{Name: "libcrypto3", Architecture: "x86_64", Manager: "apk", Source: "openssl"},
		{Name: "busybox", Architecture: "x86_64", Manager: "apk"},
		{Name: "openssl-libs", Architecture: "x86_64", Manager: "rpm", Source: "openssl-3.0.7-27.el9.src.rpm"},
		{Name: "kernel-core", Architecture: "x86_64", Manager: "dnf", Source: "kernel-5.14.0-427.13.1.el9_4.src.rpm"},
		{Name: "requests", Manager: "pip"},
	}
	at := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)
	for scan := range 40 {
		var installed []fixtures.Installed
		for _, candidate := range catalogue {
			if random.IntN(3) > 0 {
				candidate.Version = fmt.Sprintf("1.%d-%d", random.IntN(4), scan)
				installed = append(installed, candidate)
			}
		}
		fold(t, store, owner, fixtures.PackageScan{
			RecordID: fmt.Sprintf("inv-%010d", scan),
			AgentID:  fmt.Sprintf("agent-%d", random.IntN(4)),
			At:       at.Add(time.Duration(random.IntN(72)) * time.Hour),
			Packages: installed,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	connection := inspector(t, address)

	rows, err := connection.Query(ctx, `
		SELECT item.agent_id, item.item_id, item.package_name, item.package_source, item.package_manager
		FROM asset_inventory AS item FINAL
		INNER JOIN (
			SELECT tenant_id, agent_id, kind, max(scanned_at) AS scanned_at
			FROM asset_inventory_scans WHERE tenant_id = ? GROUP BY tenant_id, agent_id, kind
		) AS scan
		ON item.tenant_id = scan.tenant_id AND item.agent_id = scan.agent_id AND item.kind = scan.kind
		WHERE item.tenant_id = ? AND item.kind = 'package' AND item.last_seen >= scan.scanned_at`, owner, owner)
	if err != nil {
		t.Fatalf("read the current packages: %v", err)
	}
	var current []currentPackage
	for rows.Next() {
		var held currentPackage
		if err := rows.Scan(&held.agent, &held.item, &held.name, &held.source, &held.manager); err != nil {
			t.Fatalf("read a current package: %v", err)
		}
		current = append(current, held)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read the current packages: %v", err)
	}
	_ = rows.Close()
	if len(current) == 0 {
		t.Fatal("no package is current, so nothing was looked up")
	}

	listed, err := connection.Query(ctx, `SELECT package, agent_id, item_id FROM asset_package_holders WHERE tenant_id = ?`, owner)
	if err != nil {
		t.Fatalf("read the holders: %v", err)
	}
	holders := map[[3]string]bool{}
	for listed.Next() {
		var key [3]string
		if err := listed.Scan(&key[0], &key[1], &key[2]); err != nil {
			t.Fatalf("read a holder: %v", err)
		}
		holders[key] = true
	}
	if err := listed.Err(); err != nil {
		t.Fatalf("read the holders: %v", err)
	}
	_ = listed.Close()

	looked := 0
	for _, held := range current {
		for _, name := range vulnerability.PackageNames(&inventoryv1.Package{Name: held.name, Source: held.source, Manager: held.manager}) {
			looked++
			if !holders[[3]string{name, held.agent, held.item}] {
				t.Errorf("%s on %s is current and not held under %q", held.name, held.agent, name)
			}
		}
	}
	if looked == 0 {
		t.Fatal("no current package has a name an advisory could give it")
	}
}
