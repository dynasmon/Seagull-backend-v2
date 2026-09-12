//go:build integration

package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventorystore"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// What an asset currently has, stated once: the items of a kind whose last_seen
// is at or after the newest full enumeration of that kind. Every claim the card
// makes about absence, deltas and late records is this query answering
// differently, so the suite asks it rather than asking the writer.
const currentItems = `
	SELECT item.package_name, item.package_version
	FROM asset_inventory AS item FINAL
	INNER JOIN (
		SELECT tenant_id, agent_id, kind, max(scanned_at) AS scanned_at
		FROM asset_inventory_scans
		WHERE tenant_id = ?
		GROUP BY tenant_id, agent_id, kind
	) AS scan
	ON item.tenant_id = scan.tenant_id AND item.agent_id = scan.agent_id AND item.kind = scan.kind
	WHERE item.tenant_id = ? AND item.last_seen >= scan.scanned_at
	ORDER BY item.package_name`

func migratedInventoryStore(t *testing.T, address string) *clickhouse.InventoryStore {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	migrator, err := clickhouse.NewMigrator(storeSettings(address))
	if err != nil {
		t.Fatalf("build the migrator: %v", err)
	}
	if _, err := migrator.Apply(ctx); err != nil {
		t.Fatalf("apply the schema: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatalf("close the migrator: %v", err)
	}

	store, err := clickhouse.NewInventoryStore(storeSettings(address))
	if err != nil {
		t.Fatalf("build the inventory store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass verification: %v", err)
	}
	return store
}

func fold(t *testing.T, store *clickhouse.InventoryStore, owner string, scan fixtures.PackageScan) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	record := scan.Record()
	record.Origin.TenantId = owner

	rows := inventorystore.Project(record)
	var scans []inventorystore.Scan
	if enumerated, full := inventorystore.Scanned(record); full {
		scans = append(scans, enumerated)
	}
	if err := store.Store(ctx, rows, scans); err != nil {
		t.Fatalf("fold the record: %v", err)
	}
}

func current(t *testing.T, connection driver.Conn, owner string) map[string]string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rows, err := connection.Query(ctx, currentItems, owner, owner)
	if err != nil {
		t.Fatalf("read the current inventory: %v", err)
	}
	defer func() { _ = rows.Close() }()

	held := map[string]string{}
	for rows.Next() {
		var name, version string
		if err := rows.Scan(&name, &version); err != nil {
			t.Fatalf("read the current inventory: %v", err)
		}
		held[name] = version
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read the current inventory: %v", err)
	}
	return held
}

func TestTheInventoryStoreKeepsEveryFieldAPackageCarries(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)

	at := time.Date(2026, time.September, 12, 10, 30, 0, 0, time.UTC)
	fold(t, store, owner, fixtures.PackageScan{
		RecordID: "inv-0000000001",
		AgentID:  "web-01",
		Hostname: "web-01.acme.example",
		At:       at,
		Packages: []fixtures.Installed{{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var (
		recordID, agentID, hostname, kind, mode, collector string
		name, version, architecture, manager               string
		lastSeen                                           time.Time
	)
	err := inspector(t, address).QueryRow(ctx, `
		SELECT record_id, agent_id, host_hostname, kind, mode, collector, last_seen,
		       package_name, package_version, package_architecture, package_manager
		FROM asset_inventory FINAL WHERE tenant_id = ?`, owner,
	).Scan(&recordID, &agentID, &hostname, &kind, &mode, &collector, &lastSeen,
		&name, &version, &architecture, &manager)
	if err != nil {
		t.Fatalf("read the item back: %v", err)
	}

	for _, field := range []struct {
		name string
		got  any
		want any
	}{
		{"record_id", recordID, "inv-0000000001"},
		{"agent_id", agentID, "web-01"},
		{"host_hostname", hostname, "web-01.acme.example"},
		{"kind", kind, "package"},
		{"mode", mode, "snapshot"},
		{"collector", collector, "syscollector"},
		{"package_name", name, "curl"},
		{"package_version", version, "8.5.0"},
		{"package_architecture", architecture, "amd64"},
		{"package_manager", manager, "dpkg"},
	} {
		if field.got != field.want {
			t.Errorf("%s came back as %v, want %v", field.name, field.got, field.want)
		}
	}
	if !lastSeen.UTC().Equal(at) {
		t.Errorf("last_seen came back as %s, want %s", lastSeen.UTC(), at)
	}
}

func TestAnUpgradeReplacesTheItemRatherThanAddingOne(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: at,
		Packages: []fixtures.Installed{{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"}}})
	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: at.Add(time.Hour),
		Packages: []fixtures.Installed{{Name: "curl", Version: "8.6.0", Architecture: "amd64", Manager: "dpkg"}}})

	held := current(t, inspector(t, address), owner)
	if len(held) != 1 || held["curl"] != "8.6.0" {
		t.Fatalf("the asset holds %v, want one curl at 8.6.0", held)
	}
}

func TestARecordThatArrivesLateNeverOverwritesANewerOne(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: at.Add(time.Hour),
		Packages: []fixtures.Installed{{Name: "curl", Version: "8.6.0", Architecture: "amd64", Manager: "dpkg"}}})
	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: at,
		Packages: []fixtures.Installed{{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"}}})

	held := current(t, inspector(t, address), owner)
	if held["curl"] != "8.6.0" {
		t.Fatalf("a late record put curl back to %q", held["curl"])
	}
}

// Nothing is deleted and nothing is tombstoned: the row openssl left behind is
// still there, and it is out of the answer because the line moved past it.
func TestAnItemTheNewestSnapshotDoesNotNameStopsBeingCurrent(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	connection := inspector(t, address)
	at := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: at, Packages: []fixtures.Installed{
		{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"},
		{Name: "openssl", Version: "3.0.13", Architecture: "amd64", Manager: "dpkg"},
	}})
	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: at.Add(time.Hour), Packages: []fixtures.Installed{
		{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"},
	}})

	held := current(t, connection, owner)
	if len(held) != 1 || held["curl"] == "" {
		t.Fatalf("the asset holds %v, want curl alone", held)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var rows uint64
	if err := connection.QueryRow(ctx,
		"SELECT count() FROM asset_inventory FINAL WHERE tenant_id = ? AND package_name = 'openssl'", owner,
	).Scan(&rows); err != nil {
		t.Fatalf("count what openssl left behind: %v", err)
	}
	if rows != 1 {
		t.Fatalf("openssl left %d rows behind, want the one that says when it was last there", rows)
	}
}

// A delta says nothing about what it omits, so it refreshes what it names and
// leaves the line where it was. A delta that moved the line would retire every
// item it did not happen to mention.
func TestADeltaRefreshesWhatItNamesWithoutRetiringAnythingElse(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: at, Packages: []fixtures.Installed{
		{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"},
		{Name: "openssl", Version: "3.0.13", Architecture: "amd64", Manager: "dpkg"},
	}})
	fold(t, store, owner, fixtures.PackageScan{
		AgentID: "web-01", At: at.Add(time.Hour), Mode: inventoryv1.Mode_MODE_DELTA,
		Packages: []fixtures.Installed{
			{Name: "curl", Version: "8.6.0", Architecture: "amd64", Manager: "dpkg"},
			{Name: "jq", Version: "1.7", Architecture: "amd64", Manager: "dpkg"},
		},
	})

	held := current(t, inspector(t, address), owner)
	if len(held) != 3 {
		t.Fatalf("the asset holds %v, want curl, openssl and jq", held)
	}
	if held["curl"] != "8.6.0" {
		t.Errorf("the delta did not upgrade curl: %q", held["curl"])
	}
	if held["openssl"] != "3.0.13" {
		t.Errorf("a delta retired openssl, which it never mentioned: %q", held["openssl"])
	}
	if held["jq"] != "1.7" {
		t.Errorf("a package a delta introduced is not current: %q", held["jq"])
	}
}

func TestAnEmptySnapshotRetiresEverything(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "web-01", At: at, Packages: []fixtures.Installed{
		{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"},
	}})
	fold(t, store, owner, fixtures.PackageScan{
		AgentID: "web-01", At: at.Add(time.Hour), Packages: []fixtures.Installed{},
	})

	if held := current(t, inspector(t, address), owner); len(held) != 0 {
		t.Fatalf("an empty snapshot left %v installed", held)
	}
}

func TestFoldingTheSameRecordTwiceLeavesOneItem(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)

	scan := fixtures.PackageScan{AgentID: "web-01", At: at, Packages: []fixtures.Installed{
		{Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg"},
	}}
	fold(t, store, owner, scan)
	fold(t, store, owner, scan)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	connection := inspector(t, address)
	var items, scans uint64
	if err := connection.QueryRow(ctx,
		"SELECT count() FROM asset_inventory FINAL WHERE tenant_id = ?", owner).Scan(&items); err != nil {
		t.Fatalf("count the items: %v", err)
	}
	if err := connection.QueryRow(ctx,
		"SELECT count() FROM asset_inventory_scans FINAL WHERE tenant_id = ?", owner).Scan(&scans); err != nil {
		t.Fatalf("count the scans: %v", err)
	}
	if items != 1 || scans != 1 {
		t.Fatalf("a replayed record left %d items and %d scans, want one of each", items, scans)
	}
}
