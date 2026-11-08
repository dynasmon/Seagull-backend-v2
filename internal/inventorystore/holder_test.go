package inventorystore

import (
	"context"
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func installedItem(name, version, source, manager string) *inventoryv1.Item {
	return &inventoryv1.Item{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{
		Name:         name,
		Version:      version,
		Architecture: "amd64",
		Manager:      manager,
		Source:       source,
	}}}
}

func heldUnder(holders []Holder) map[string][]string {
	names := map[string][]string{}
	for _, holder := range holders {
		names[holder.ItemID] = append(names[holder.ItemID], holder.Package)
	}
	for item := range names {
		slices.Sort(names[item])
	}
	return names
}

func TestAPackageIsHeldUnderEveryNameAnAdvisoryMayCallIt(t *testing.T) {
	rows := Project(record(inventoryv1.Kind_KIND_PACKAGE,
		installedItem("libssl3", "3.0.11-1~deb12u2+b1", "openssl (3.0.11-1~deb12u2)", "dpkg"),
		installedItem("curl", "7.88.1-10+deb12u5", "", "dpkg"),
		installedItem("openssl-libs", "1:3.0.7-27.el9", "openssl-3.0.7-27.el9.src.rpm", "rpm"),
		installedItem("libcrypto3", "3.1.4-r5", "openssl", "apk"),
		installedItem("requests", "2.31.0", "", "pip"),
	))

	held := heldUnder(Holders(rows))
	for _, row := range rows {
		want := vulnerability.PackageNames(&inventoryv1.Package{Name: row.PackageName, Source: row.PackageSource, Manager: row.PackageManager})
		slices.Sort(want)
		if got := held[row.ItemID]; !slices.Equal(got, want) {
			t.Errorf("%s is held under %q, want %q", row.PackageName, got, want)
		}
	}
	for name, want := range map[string][]string{
		"libssl3":      {"openssl"},
		"curl":         {"curl"},
		"openssl-libs": {"openssl", "openssl-libs"},
		"libcrypto3":   {"openssl"},
	} {
		index := slices.IndexFunc(rows, func(row Row) bool { return row.PackageName == name })
		if got := held[rows[index].ItemID]; !slices.Equal(got, want) {
			t.Errorf("%s is held under %q, want %q", name, got, want)
		}
	}
	if got := held[rows[4].ItemID]; len(got) != 0 {
		t.Errorf("a package no distribution's advisories describe is held under %q", got)
	}
}

func TestAHolderCarriesTheAssetItemAndObservationOfItsRow(t *testing.T) {
	rows := Project(record(inventoryv1.Kind_KIND_PACKAGE, installedItem("libssl3", "3.0.13-1", "openssl", "dpkg")))
	holders := Holders(rows)
	if len(holders) != 1 {
		t.Fatalf("one package became %d holders", len(holders))
	}
	want := Holder{Package: "openssl", TenantID: "acme", AgentID: "web-01", ItemID: rows[0].ItemID, LastSeen: collected}
	if holders[0] != want {
		t.Fatalf("the holder is %+v, want %+v", holders[0], want)
	}
}

func TestOnlyAPackageHasHolders(t *testing.T) {
	for kind := range groups {
		if kind == inventoryv1.Kind_KIND_PACKAGE {
			continue
		}
		if holders := Holders(Project(record(kind, filled(kind)))); len(holders) != 0 {
			t.Errorf("a %s item is held under %d names", kind, len(holders))
		}
	}
}

func TestTheProjectorStoresTheHoldersOfTheRowsItStores(t *testing.T) {
	source := &reader{records: []Record{fetched(t, record(inventoryv1.Kind_KIND_PACKAGE,
		installedItem("libssl3", "3.0.13-1", "openssl", "dpkg"), installedItem("curl", "8.5.0-2", "", "dpkg")))}}
	sink := &folded{}

	if err := projector(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if want := Holders(sink.rows[0]); len(want) != 2 || !slices.Equal(sink.holders[0], want) {
		t.Fatalf("the store was handed holders %+v for rows held as %+v", sink.holders[0], want)
	}
}
