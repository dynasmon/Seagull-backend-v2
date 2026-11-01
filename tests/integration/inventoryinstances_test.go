//go:build integration

package integration_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// What the database of a Rocky Linux 9 host said once two kernels were installed
// side by side: one name, one upstream version, two releases.
const (
	olderKernel = "5.14.0-687.60.1.el9_8"
	newerKernel = "5.14.0-687.61.1.el9_8"
)

// The map current answers with has one version a name, which is the question a
// host with two kernels is about, so this one lists what the store holds.
func instances(t *testing.T, connection driver.Conn, query, owner string) []string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rows, err := connection.Query(ctx, query, owner, owner)
	if err != nil {
		t.Fatalf("read the current inventory: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var held []string
	for rows.Next() {
		var name, detail string
		if err := rows.Scan(&name, &detail); err != nil {
			t.Fatalf("read the current inventory: %v", err)
		}
		held = append(held, name+" "+detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read the current inventory: %v", err)
	}
	slices.Sort(held)
	return held
}

func storedRows(t *testing.T, connection driver.Conn, owner, condition string) uint64 {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var rows uint64
	if err := connection.QueryRow(ctx,
		"SELECT count() FROM asset_inventory FINAL WHERE tenant_id = ? AND "+condition, owner,
	).Scan(&rows); err != nil {
		t.Fatalf("count the stored rows: %v", err)
	}
	return rows
}

func kernels(versions ...string) []fixtures.Installed {
	installed := make([]fixtures.Installed, len(versions))
	for index, version := range versions {
		installed[index] = fixtures.Installed{Name: "kernel-core", Version: version, Architecture: "x86_64", Manager: "rpm"}
	}
	return installed
}

func TestTwoInstalledKernelsAreTwoCurrentItems(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	at := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "rocky-01", At: at, Packages: kernels(newerKernel, olderKernel)})

	held := instances(t, inspector(t, address), currentItems, owner)
	want := []string{"kernel-core " + olderKernel, "kernel-core " + newerKernel}
	if !slices.Equal(held, want) {
		t.Fatalf("the asset holds %q, want both kernels", held)
	}
}

func TestASnapshotWithoutTheOldKernelRetiresIt(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	connection := inspector(t, address)
	at := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)

	for step, installed := range [][]string{{olderKernel}, {olderKernel, newerKernel}, {newerKernel}} {
		fold(t, store, owner, fixtures.PackageScan{
			AgentID: "rocky-01", At: at.Add(time.Duration(step) * time.Hour), Packages: kernels(installed...),
		})

		want := make([]string, len(installed))
		for index, version := range installed {
			want[index] = "kernel-core " + version
		}
		if held := instances(t, connection, currentItems, owner); !slices.Equal(held, want) {
			t.Fatalf("after step %d the asset holds %q, want %q", step, held, want)
		}
	}

	if rows := storedRows(t, connection, owner, "package_version = '"+olderKernel+"'"); rows == 0 {
		t.Fatal("the retired kernel left no row saying when it was last there")
	}
}

func TestAnUpgradeARecordShowsAloneReplacesItsRowWhereTheManagerCouldHoldBoth(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	connection := inspector(t, address)
	at := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)

	for step, version := range []string{"1:3.5.8-1.el9_8", "1:3.5.8-2.el9_8"} {
		fold(t, store, owner, fixtures.PackageScan{
			AgentID: "rocky-01", At: at.Add(time.Duration(step) * time.Hour),
			Packages: []fixtures.Installed{{Name: "openssl-libs", Version: version, Architecture: "x86_64", Manager: "rpm"}},
		})
	}

	if held := current(t, connection, owner); held["openssl-libs"] != "1:3.5.8-2.el9_8" {
		t.Fatalf("the asset holds %q, want the upgraded version", held["openssl-libs"])
	}
	if rows := storedRows(t, connection, owner, "package_name = 'openssl-libs'"); rows != 1 {
		t.Fatalf("an upgrade left %d rows, want the one it replaced", rows)
	}
}

func TestADeltaLeavesTheKernelItDidNotNameInstalled(t *testing.T) {
	address := storeAddress(t)
	store := migratedInventoryStore(t, address)
	owner := tenant(t)
	connection := inspector(t, address)
	at := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)

	fold(t, store, owner, fixtures.PackageScan{AgentID: "rocky-01", At: at, Packages: kernels(olderKernel)})
	fold(t, store, owner, fixtures.PackageScan{
		AgentID: "rocky-01", At: at.Add(time.Hour), Mode: inventoryv1.Mode_MODE_DELTA, Packages: kernels(newerKernel),
	})

	held := instances(t, connection, currentItems, owner)
	want := []string{"kernel-core " + olderKernel, "kernel-core " + newerKernel}
	if !slices.Equal(held, want) {
		t.Fatalf("after the delta the asset holds %q, want both kernels", held)
	}
}
