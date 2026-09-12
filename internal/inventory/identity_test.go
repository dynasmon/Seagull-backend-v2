package inventory

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func TestEveryDeclaredKindIsShaped(t *testing.T) {
	for value, name := range inventoryv1.Kind_name {
		kind := inventoryv1.Kind(value)
		if kind == inventoryv1.Kind_KIND_UNSPECIFIED {
			continue
		}
		if !Shaped(kind) {
			t.Errorf("the contract declares %s and this build cannot identify an item of it", name)
		}
	}
}

func TestAPackageIsIdentifiedByNameArchitectureAndManager(t *testing.T) {
	base := packageItem("curl", "8.5.0", "amd64", "dpkg")

	same := ItemID(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.9.1", "amd64", "dpkg"))
	if ItemID(inventoryv1.Kind_KIND_PACKAGE, base) != same {
		t.Error("the same package at two versions is two items, so an upgrade would never replace anything")
	}

	for name, other := range map[string]*inventoryv1.Item{
		"another name":         packageItem("curl-minimal", "8.5.0", "amd64", "dpkg"),
		"another architecture": packageItem("curl", "8.5.0", "arm64", "dpkg"),
		"another manager":      packageItem("curl", "8.5.0", "amd64", "pip"),
	} {
		if ItemID(inventoryv1.Kind_KIND_PACKAGE, base) == ItemID(inventoryv1.Kind_KIND_PACKAGE, other) {
			t.Errorf("%s shares an identity with the package it is not", name)
		}
	}
}

// The whole reason the digest covers the length of every part. Concatenating
// them would let one package's fields spell another's, and an asset would hold
// one row where it has two packages.
func TestOnePackageCannotSpellAnother(t *testing.T) {
	left := ItemID(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "1", "amd64", "dpkg"))
	right := ItemID(inventoryv1.Kind_KIND_PACKAGE, packageItem("curlamd64", "1", "", "dpkg"))
	if left == right {
		t.Error("two packages were folded into one identity by concatenation")
	}
}

func TestAKindOfItsOwnNeverSharesAnIdentity(t *testing.T) {
	seen := map[string]string{}
	for kind := range shapes {
		identifier := ItemID(kind, filled(kind))
		if identifier == "" {
			t.Errorf("%s has no identity", KindName(kind))
			continue
		}
		if previous, taken := seen[identifier]; taken {
			t.Errorf("%s and %s share the identity %s", KindName(kind), previous, identifier)
		}
		seen[identifier] = KindName(kind)
	}
}

// A singleton is one row per asset whatever it reports, so a machine that
// changes its kernel replaces the row rather than accumulating one per release.
func TestASingletonKeepsOneIdentityWhateverItReports(t *testing.T) {
	first := &inventoryv1.Item{Body: &inventoryv1.Item_Kernel{
		Kernel: &inventoryv1.Kernel{Name: "Linux", Release: "6.8.0-40-generic"},
	}}
	second := &inventoryv1.Item{Body: &inventoryv1.Item_Kernel{
		Kernel: &inventoryv1.Kernel{Name: "Linux", Release: "6.8.0-51-generic"},
	}}

	if ItemID(inventoryv1.Kind_KIND_KERNEL, first) != ItemID(inventoryv1.Kind_KIND_KERNEL, second) {
		t.Error("a kernel upgrade left the asset holding two kernels")
	}
}

func TestAnAccountIsIdentifiedByItsIdentifierAndNotItsName(t *testing.T) {
	renamed := ItemID(inventoryv1.Kind_KIND_USER, userItem("deploy", "1001"))
	if ItemID(inventoryv1.Kind_KIND_USER, userItem("deployment", "1001")) != renamed {
		t.Error("a renamed account became a second account")
	}
	if ItemID(inventoryv1.Kind_KIND_USER, userItem("deploy", "1002")) == renamed {
		t.Error("a freed name reused by another account shares its identity")
	}
	if ItemID(inventoryv1.Kind_KIND_USER, userItem("deploy", "")) == renamed {
		t.Error("an account with no identifier was folded into one that has one")
	}
}

// A pid is reused within minutes, so what tells two processes apart is when
// each of them started.
func TestAReusedProcessIdentifierIsNotTheSameProcess(t *testing.T) {
	first := processItem(4021, 1_700_000_000)
	second := processItem(4021, 1_700_000_900)
	if ItemID(inventoryv1.Kind_KIND_PROCESS, first) == ItemID(inventoryv1.Kind_KIND_PROCESS, second) {
		t.Error("a recycled pid was read as the process that held it before")
	}
}

func TestAnUnknownKindIsNamedRatherThanNumbered(t *testing.T) {
	if name := KindName(inventoryv1.Kind(4242)); name != "unknown" {
		t.Errorf("an undeclared kind is labelled %q", name)
	}
	if name := KindName(inventoryv1.Kind_KIND_NETWORK_INTERFACE); name != "network_interface" {
		t.Errorf("a declared kind is labelled %q", name)
	}
	if name := ModeName(inventoryv1.Mode_MODE_SNAPSHOT); name != "snapshot" {
		t.Errorf("a declared mode is labelled %q", name)
	}
}

func packageItem(name, version, architecture, manager string) *inventoryv1.Item {
	return &inventoryv1.Item{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{
		Name:         name,
		Version:      version,
		Architecture: architecture,
		Manager:      manager,
	}}}
}

func userItem(name, uid string) *inventoryv1.Item {
	return &inventoryv1.Item{Body: &inventoryv1.Item_User{User: &inventoryv1.User{Name: name, Uid: uid}}}
}

func processItem(pid uint32, started int64) *inventoryv1.Item {
	return &inventoryv1.Item{Body: &inventoryv1.Item_Process{Process: &inventoryv1.Process{
		Pid:       pid,
		Name:      "nginx",
		StartedAt: timestamppb.New(time.Unix(started, 0).UTC()),
	}}}
}

// One item of every kind, each carrying what identifies it, so a test can walk
// the whole table rather than naming eight literals.
func filled(kind inventoryv1.Kind) *inventoryv1.Item {
	switch kind {
	case inventoryv1.Kind_KIND_OPERATING_SYSTEM:
		return &inventoryv1.Item{Body: &inventoryv1.Item_OperatingSystem{
			OperatingSystem: &inventoryv1.OperatingSystem{Name: "Ubuntu", Version: "24.04", Platform: "ubuntu"},
		}}
	case inventoryv1.Kind_KIND_KERNEL:
		return &inventoryv1.Item{Body: &inventoryv1.Item_Kernel{
			Kernel: &inventoryv1.Kernel{Name: "Linux", Release: "6.8.0-40-generic"},
		}}
	case inventoryv1.Kind_KIND_HARDWARE:
		return &inventoryv1.Item{Body: &inventoryv1.Item_Hardware{
			Hardware: &inventoryv1.Hardware{CpuName: "AMD EPYC 7543", CpuCores: 32},
		}}
	case inventoryv1.Kind_KIND_PACKAGE:
		return packageItem("curl", "8.5.0", "amd64", "dpkg")
	case inventoryv1.Kind_KIND_SERVICE:
		return &inventoryv1.Item{Body: &inventoryv1.Item_Service{
			Service: &inventoryv1.Service{Name: "sshd", State: inventoryv1.Service_STATE_RUNNING},
		}}
	case inventoryv1.Kind_KIND_NETWORK_INTERFACE:
		return &inventoryv1.Item{Body: &inventoryv1.Item_NetworkInterface{
			NetworkInterface: &inventoryv1.NetworkInterface{Name: "eth0", Addresses: []string{"10.0.0.5/24"}},
		}}
	case inventoryv1.Kind_KIND_USER:
		return userItem("deploy", "1001")
	case inventoryv1.Kind_KIND_PROCESS:
		return processItem(4021, 1_700_000_000)
	default:
		return &inventoryv1.Item{}
	}
}
