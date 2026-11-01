package inventorystore

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func TestARowCarriesTheIdentityOfItsOwnItem(t *testing.T) {
	rows := Project(record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.5.0"), packageItem("openssl", "3.0.13")))

	if rows[0].PackageName != "curl" || rows[0].ItemID != "a232cc002c99c96b02cdad3672325f0a1d273eafea3b0f62ec289103d37ce1d7" {
		t.Fatalf("curl was stored under %s, as %q", rows[0].ItemID, rows[0].PackageName)
	}
}

// The two things the store does with a row, without the store: one row per item
// with the newest winning, and the line only a snapshot moves.
type asset struct {
	rows map[string]Row
	line time.Time
}

func (a *asset) fold(record *inventoryv1.Record) {
	for _, row := range Project(record) {
		if held, stored := a.rows[row.ItemID]; !stored || !row.LastSeen.Before(held.LastSeen) {
			a.rows[row.ItemID] = row
		}
	}
	if scan, full := Scanned(record); full && scan.ScannedAt.After(a.line) {
		a.line = scan.ScannedAt
	}
}

func (a *asset) installed() []string {
	var held []string
	for _, row := range a.rows {
		if !row.LastSeen.Before(a.line) {
			held = append(held, row.PackageName+" "+row.PackageVersion)
		}
	}
	slices.Sort(held)
	return slices.Compact(held)
}

func randomScan(random *rand.Rand, at time.Time) (*inventoryv1.Record, []string) {
	var (
		items []*inventoryv1.Item
		named []string
	)
	add := func(name, version, architecture, manager string) {
		items = append(items, &inventoryv1.Item{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{
			Name: name, Version: version, Architecture: architecture, Manager: manager,
		}}})
		named = append(named, name+" "+version)
	}
	for _, name := range []string{"curl", "libc6", "openssl"} {
		if random.IntN(4) > 0 {
			add(name, fmt.Sprintf("%d.0", random.IntN(4)), "amd64", "dpkg")
		}
	}
	for _, name := range []string{"kernel-core", "openssl-libs", "gpg-pubkey"} {
		for _, version := range random.Perm(4)[:random.IntN(4)] {
			add(name, fmt.Sprintf("%d-1.el9", version), "x86_64", "rpm")
		}
	}

	scan := record(inventoryv1.Kind_KIND_PACKAGE, items...)
	scan.CollectedAt = timestamppb.New(at)
	slices.Sort(named)
	return scan, named
}

// The whole of what ADR 27 promises an asset: what it has is what its newest
// full scan named, in whatever order the backbone delivered the scans.
func TestTheCurrentPackagesOfAnAssetAreWhatItsNewestSnapshotNamed(t *testing.T) {
	for seed := range uint64(64) {
		random := rand.New(rand.NewPCG(seed, 49))

		scans := make([]*inventoryv1.Record, 24)
		var newest []string
		for index := range scans {
			scans[index], newest = randomScan(random, collected.Add(time.Duration(index)*time.Hour))
		}

		inOrder := &asset{rows: map[string]Row{}}
		for _, scan := range scans {
			inOrder.fold(scan)
		}
		if got := inOrder.installed(); !slices.Equal(got, newest) {
			t.Fatalf("seed %d: the asset holds %q and its newest scan named %q", seed, got, newest)
		}

		shuffled := &asset{rows: map[string]Row{}}
		for _, index := range random.Perm(len(scans)) {
			shuffled.fold(scans[index])
		}
		if got := shuffled.installed(); !slices.Equal(got, newest) {
			t.Fatalf("seed %d, out of order: the asset holds %q and its newest scan named %q", seed, got, newest)
		}
	}
}

// A delta cannot retire what it leaves out, so an instance can outlive its
// package until the next snapshot and none is ever lost to one: a manager that
// holds one version moves on, and every other keeps all it was told about.
func TestADeltaNeverCostsAnAssetAnInstance(t *testing.T) {
	for seed := range uint64(64) {
		random := rand.New(rand.NewPCG(seed, 50))

		scan, named := randomScan(random, collected)
		held := &asset{rows: map[string]Row{}}
		held.fold(scan)

		want := slices.Clone(named)
		for step := 1; step <= 8; step++ {
			change, _ := randomScan(random, collected.Add(time.Duration(step)*time.Hour))
			change.Mode = inventoryv1.Mode_MODE_DELTA
			for _, item := range change.GetItems() {
				installed := item.GetPackage()
				if installed.GetManager() == "dpkg" {
					want = slices.DeleteFunc(want, func(entry string) bool {
						return strings.HasPrefix(entry, installed.GetName()+" ")
					})
				}
				want = append(want, installed.GetName()+" "+installed.GetVersion())
			}
			held.fold(change)
		}
		slices.Sort(want)
		want = slices.Compact(want)

		if got := held.installed(); !slices.Equal(got, want) {
			t.Fatalf("seed %d: the asset holds %q, want %q", seed, got, want)
		}
	}
}
