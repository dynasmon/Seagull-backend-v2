package inventory

import (
	"slices"
	"testing"

	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const (
	packages = inventoryv1.Kind_KIND_PACKAGE
	accounts = inventoryv1.Kind_KIND_USER

	olderKernel = "5.14.0-687.60.1.el9_8"
	newerKernel = "5.14.0-687.61.1.el9_8"

	curlUnderDpkg    = "a232cc002c99c96b02cdad3672325f0a1d273eafea3b0f62ec289103d37ce1d7"
	kernelAlone      = "a9e24e281bc79997df13e62c1691392ab7c4c664712fe56eb46c52ecd4cf267d"
	kernelAtOlder    = "9bad24003bc210dbb77c9b2a1204a53fc73606e0cbc1db879e433c746b4b02dd"
	kernelAtNewer    = "32fff66ce2cbaf3b70e183f1600e844f0ecc3a4406ec62f3f2800db86ae58670"
	uidZeroAlone     = "458b3db87d1aea56f6ad96610eebfead8ea6dad6770b8367989116522298c293"
	uidZeroAsRoot    = "600fc560f65d8c526445ac945445d514527af912b4c65ac28f7946a2c5acb61b"
	uidZeroAsToor    = "f20635adb5fafe19f002eb0a996fd35b78566090a8fc4af16e33b50f77e8d60c"
	accountByItsName = "bb387338218bee71a98acf816aba58ba9cd1badda9de60dca95975c2f7c2136c"
)

func snapshot(kind inventoryv1.Kind, items ...*inventoryv1.Item) *inventoryv1.Record {
	return &inventoryv1.Record{Kind: kind, Mode: inventoryv1.Mode_MODE_SNAPSHOT, Items: items}
}

func delta(kind inventoryv1.Kind, items ...*inventoryv1.Item) *inventoryv1.Record {
	return &inventoryv1.Record{Kind: kind, Mode: inventoryv1.Mode_MODE_DELTA, Items: items}
}

func kernel(version string) *inventoryv1.Item {
	return packageItem("kernel-core", version, "x86_64", "rpm")
}

// The digests are worked out by hand from the layout ItemID documents. A replay
// rewrites every row under these names, so a change to one of them leaves an
// asset holding a package twice, and no other test would say so.
func TestWhatAStoreAlreadyHoldsKeepsItsName(t *testing.T) {
	for name, held := range map[string]struct {
		record *inventoryv1.Record
		want   string
	}{
		"a package of a manager that holds one": {snapshot(packages, packageItem("curl", "8.5.0", "amd64", "dpkg")), curlUnderDpkg},
		"a version a database shows alone":      {snapshot(packages, kernel(olderKernel)), kernelAlone},
		"an account alone under its uid":        {snapshot(accounts, userItem("root", "0")), uidZeroAlone},
	} {
		if got := ItemIDs(held.record); !slices.Equal(got, []string{held.want}) {
			t.Errorf("%s is named %q, want %s", name, got, held.want)
		}
	}
}

func TestEachVersionARecordShowsIsNamedByIt(t *testing.T) {
	got := ItemIDs(snapshot(packages, kernel(olderKernel), kernel(newerKernel)))
	if !slices.Equal(got, []string{kernelAtOlder, kernelAtNewer}) {
		t.Fatalf("two kernels are named %q", got)
	}
}

// What a Rocky Linux 9 database held twice. Only the kernels say they are
// install-only: the keys and the half-finished upgrade are the reason no list of
// names could decide this.
func TestEveryNameADatabaseHoldsTwiceIsKeptApart(t *testing.T) {
	for _, held := range []struct{ name, first, second, architecture string }{
		{"kernel-core", olderKernel, newerKernel, "x86_64"},
		{"kernel-modules-core", olderKernel, newerKernel, "x86_64"},
		{"gpg-pubkey", "350d275d-6279464b", "95ae3d91-62678c43", "(none)"},
		{"openssl-libs", "1:3.5.8-1.el9_8", "1:3.5.8-2.el9_8", "x86_64"},
	} {
		got := ItemIDs(snapshot(packages,
			packageItem(held.name, held.first, held.architecture, "rpm"),
			packageItem(held.name, held.second, held.architecture, "rpm"),
		))
		if got[0] == got[1] {
			t.Errorf("two versions of %s took one identity, so the store keeps one of them", held.name)
		}
	}
}

func TestAManagerNotDeclaredToHoldOneKeepsEveryVersionItShows(t *testing.T) {
	for _, manager := range []string{"rpm", "dnf", "yum", "pip", ""} {
		got := ItemIDs(snapshot(packages,
			packageItem("requests", "2.31.0", "noarch", manager),
			packageItem("requests", "2.32.3", "noarch", manager),
		))
		if got[0] == got[1] {
			t.Errorf("%q folded two versions it could hold side by side", manager)
		}
	}
}

func TestAManagerThatHoldsOneNeverNamesAPackageByItsVersion(t *testing.T) {
	for _, manager := range []string{"dpkg", "apt", "apk"} {
		alone := ItemIDs(snapshot(packages, packageItem("curl", "8.5.0", "amd64", manager)))
		both := ItemIDs(snapshot(packages,
			packageItem("curl", "8.5.0", "amd64", manager),
			packageItem("curl", "8.6.0", "amd64", manager),
		))
		if both[0] != alone[0] || both[1] != alone[0] {
			t.Errorf("%s moved a package off the row it has, and its manager can only hold the one", manager)
		}
	}
}

func TestAVersionShownAloneKeepsTheIdentityAnUpgradeReplaces(t *testing.T) {
	before := ItemIDs(snapshot(packages, packageItem("openssl-libs", "1:3.5.8-1.el9_8", "x86_64", "rpm")))
	after := ItemIDs(snapshot(packages, packageItem("openssl-libs", "1:3.5.8-2.el9_8", "x86_64", "rpm")))
	if before[0] != after[0] {
		t.Error("an upgrade took a new identity, so it left the version it replaced behind")
	}
}

func TestAnItemIsNamedWhereverARecordNamesIt(t *testing.T) {
	forward := ItemIDs(snapshot(packages, kernel(olderKernel), kernel(newerKernel)))
	reversed := ItemIDs(snapshot(packages, kernel(newerKernel), kernel(olderKernel)))
	if forward[0] != reversed[1] || forward[1] != reversed[0] {
		t.Errorf("a kernel changed its name with its place: %q and %q", forward, reversed)
	}
}

func TestOneVersionNamedTwiceIsOneInstance(t *testing.T) {
	got := ItemIDs(snapshot(packages, kernel(olderKernel), kernel(olderKernel)))
	if !slices.Equal(got, []string{kernelAlone, kernelAlone}) {
		t.Fatalf("one kernel named twice is named %q", got)
	}
}

func TestOnePackageShownTwiceLeavesEveryOtherAsItWas(t *testing.T) {
	got := ItemIDs(snapshot(packages,
		kernel(olderKernel),
		kernel(newerKernel),
		packageItem("kernel-core", olderKernel, "aarch64", "rpm"),
		packageItem("curl", "8.5.0", "amd64", "dpkg"),
	))
	alone := ItemIDs(snapshot(packages, packageItem("kernel-core", olderKernel, "aarch64", "rpm")))
	if got[2] != alone[0] {
		t.Error("two kernels of one architecture renamed the kernel of another")
	}
	if got[3] != curlUnderDpkg {
		t.Error("two kernels renamed a package that has nothing to do with them")
	}
}

// Neither of the two versions a database shows can be spelled into the other
// package by moving letters between what the digest covers.
func TestOneInstanceCannotSpellAnother(t *testing.T) {
	left := ItemIDs(snapshot(packages, packageItem("n", "1", "a", "rpm"), packageItem("n", "2", "a", "rpm")))
	right := ItemIDs(snapshot(packages, packageItem("n", "m1", "a", "rp"), packageItem("n", "m2", "a", "rp")))
	if left[0] == right[0] || left[1] == right[1] {
		t.Error("the version was folded into the manager by concatenation")
	}
}

// A delta shows part of an asset, so it cannot say a version replaced another.
func TestADeltaNamesAVersionItsManagerCouldHoldBesideAnother(t *testing.T) {
	if got := ItemIDs(delta(packages, kernel(olderKernel))); !slices.Equal(got, []string{kernelAtOlder}) {
		t.Fatalf("a delta names a kernel %q, which is not the row a snapshot showing two wrote", got)
	}
}

func TestADeltaOfAManagerThatHoldsOneStillReplaces(t *testing.T) {
	got := ItemIDs(delta(packages, packageItem("curl", "8.6.0", "amd64", "dpkg")))
	if !slices.Equal(got, []string{curlUnderDpkg}) {
		t.Fatalf("a delta names curl %q, so an upgrade would add a row to replace", got)
	}
}

func TestEachAccountARecordShowsUnderOneUidIsNamedByItsName(t *testing.T) {
	got := ItemIDs(snapshot(accounts, userItem("root", "0"), userItem("toor", "0")))
	if !slices.Equal(got, []string{uidZeroAsRoot, uidZeroAsToor}) {
		t.Fatalf("two accounts of uid 0 are named %q", got)
	}
}

func TestARenamedAccountShownAloneIsTheSameAccount(t *testing.T) {
	before := ItemIDs(snapshot(accounts, userItem("deploy", "1001")))
	after := ItemIDs(snapshot(accounts, userItem("deployment", "1001")))
	if before[0] != after[0] {
		t.Error("a rename took a new identity")
	}
}

func TestAnAccountWithoutAUidIsAlreadyToldApartByItsName(t *testing.T) {
	alone := ItemIDs(delta(accounts, userItem("deploy", "")))
	if !slices.Equal(alone, []string{accountByItsName}) {
		t.Fatalf("an account named by its name is named %q, which names it twice", alone)
	}
}

func TestAKindThatHasNothingToTellApartStaysFolded(t *testing.T) {
	sshd := filled(inventoryv1.Kind_KIND_SERVICE)
	got := ItemIDs(snapshot(inventoryv1.Kind_KIND_SERVICE, sshd, sshd))
	if got[0] != got[1] {
		t.Errorf("one service took two identities: %q", got)
	}
}

func TestARecordWithNoItemsNamesNothing(t *testing.T) {
	if got := ItemIDs(snapshot(packages)); len(got) != 0 {
		t.Fatalf("an empty snapshot named %q", got)
	}
}
