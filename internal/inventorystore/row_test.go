package inventorystore

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const wellKnown = "google.protobuf."

var collected = time.Date(2026, time.September, 12, 12, 0, 0, 0, time.UTC)

// Which columns belong to which kind. An item is one thing, so a row carries one
// of these groups and leaves the other seven at their zero value.
var groups = map[inventoryv1.Kind]string{
	inventoryv1.Kind_KIND_OPERATING_SYSTEM:  "OS",
	inventoryv1.Kind_KIND_KERNEL:            "Kernel",
	inventoryv1.Kind_KIND_PACKAGE:           "Package",
	inventoryv1.Kind_KIND_SERVICE:           "Service",
	inventoryv1.Kind_KIND_NETWORK_INTERFACE: "Interface",
	inventoryv1.Kind_KIND_USER:              "User",
	inventoryv1.Kind_KIND_HARDWARE:          "Hardware",
	inventoryv1.Kind_KIND_PROCESS:           "Process",
}

// The rule runs from the contract towards the store, never the other way, so a
// collector cannot start reporting something and have it quietly stop being
// kept. Items are walked into rather than treated as a leaf: the projection is
// one row per item, so how each one is stored has been decided field by field.
func TestTheContractCannotGrowWithoutTheInventoryStoreNoticing(t *testing.T) {
	walked := leaves((&inventoryv1.Record{}).ProtoReflect().Descriptor(), "")
	slices.Sort(walked)

	kept := slices.Clone(carried)
	slices.Sort(kept)

	if slices.Equal(walked, kept) {
		return
	}
	for _, path := range walked {
		if !slices.Contains(kept, path) {
			t.Errorf("a record carries %s and the store does not keep it", path)
		}
	}
	for _, path := range kept {
		if !slices.Contains(walked, path) {
			t.Errorf("the store claims to keep %s and the contract has no such field", path)
		}
	}
}

func leaves(message protoreflect.MessageDescriptor, prefix string) []string {
	var paths []string
	fields := message.Fields()
	for index := range fields.Len() {
		field := fields.Get(index)
		path := prefix + string(field.Name())

		nested := field.Kind() == protoreflect.MessageKind && !field.IsMap() &&
			!strings.HasPrefix(string(field.Message().FullName()), wellKnown)
		if nested {
			paths = append(paths, leaves(field.Message(), path+".")...)
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

func TestEveryKindLandsInItsOwnColumnsAndNobodyElses(t *testing.T) {
	for kind, group := range groups {
		rows := Project(record(kind, filled(kind)))
		if len(rows) != 1 {
			t.Fatalf("%s projected %d rows", group, len(rows))
		}

		value := reflect.ValueOf(rows[0])
		for index := range value.NumField() {
			field := value.Type().Field(index).Name
			owner, held := owning(field)
			switch {
			case !held:
				continue
			case owner == group && absent(value.Field(index)):
				t.Errorf("%s stays empty although a %s item set it", field, group)
			case owner != group && !absent(value.Field(index)):
				t.Errorf("%s holds %v on a %s row", field, value.Field(index).Interface(), group)
			}
		}
	}
}

func absent(value reflect.Value) bool {
	if at, held := value.Interface().(time.Time); held {
		return at.Equal(epoch)
	}
	return value.IsZero()
}

func owning(field string) (string, bool) {
	for _, group := range groups {
		if strings.HasPrefix(field, group) {
			return group, true
		}
	}
	return "", false
}

func TestOneRecordBecomesOneRowPerItemUnderOneIdentity(t *testing.T) {
	rows := Project(record(inventoryv1.Kind_KIND_PACKAGE,
		packageItem("curl", "8.5.0"), packageItem("openssl", "3.0.13"), packageItem("curl", "8.6.0")))

	if len(rows) != 3 {
		t.Fatalf("three items projected %d rows", len(rows))
	}
	if rows[0].ItemID != rows[2].ItemID {
		t.Error("the same package at two versions took two identities, so an upgrade would leave the old one installed")
	}
	if rows[0].ItemID == rows[1].ItemID {
		t.Error("two packages share an identity")
	}
	for _, row := range rows {
		if row.TenantID != "acme" || row.AgentID != "web-01" || row.Kind != "package" {
			t.Errorf("an item lost the record it came from: %+v", row)
		}
		if !row.LastSeen.Equal(collected) {
			t.Errorf("last_seen is %s and the collector looked at %s", row.LastSeen, collected)
		}
	}
}

func TestOnlyASnapshotIsAScan(t *testing.T) {
	snapshot := record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.5.0"))
	scan, full := Scanned(snapshot)
	if !full {
		t.Fatal("a snapshot did not move the line absence is measured against")
	}
	if scan.TenantID != "acme" || scan.AgentID != "web-01" || scan.Kind != "package" || scan.Items != 1 {
		t.Errorf("the scan does not name what was enumerated: %+v", scan)
	}
	if !scan.ScannedAt.Equal(collected) {
		t.Errorf("scanned_at is %s and the collector looked at %s", scan.ScannedAt, collected)
	}

	delta := record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.5.0"))
	delta.Mode = inventoryv1.Mode_MODE_DELTA
	if _, full := Scanned(delta); full {
		t.Error("a delta moved the line, so every item it did not name would read as uninstalled")
	}
}

// An empty snapshot is how a collector says the asset has none of that kind, so
// it retires everything by moving the line and writing no rows.
func TestAnEmptySnapshotIsAScanWithNoRows(t *testing.T) {
	empty := record(inventoryv1.Kind_KIND_PACKAGE)

	if rows := Project(empty); len(rows) != 0 {
		t.Fatalf("an empty snapshot projected %d rows", len(rows))
	}
	if _, full := Scanned(empty); !full {
		t.Error("an empty snapshot did not move the line, so nothing it dropped would ever be retired")
	}
}

func TestAnUnspecifiedEnumIsStoredAsAbsent(t *testing.T) {
	rows := Project(record(inventoryv1.Kind_KIND_SERVICE, &inventoryv1.Item{
		Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "sshd"}},
	}))

	if rows[0].ServiceState != "" {
		t.Fatalf("a state the collector could not read reached the store as %q", rows[0].ServiceState)
	}
}

func TestAnEnumIsStoredUnderItsOwnNameWithoutThePrefix(t *testing.T) {
	rows := Project(record(inventoryv1.Kind_KIND_SERVICE, filled(inventoryv1.Kind_KIND_SERVICE)))

	if rows[0].ServiceState != "running" {
		t.Fatalf("a running service reached the store as %q", rows[0].ServiceState)
	}
	if rows[0].Mode != "snapshot" || rows[0].Kind != "service" {
		t.Fatalf("the record's own enums reached the store as %q and %q", rows[0].Mode, rows[0].Kind)
	}
}

func TestAnAbsentTimestampIsStoredAsTheEpoch(t *testing.T) {
	bare := record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.5.0"))
	bare.Reception = nil

	row := Project(bare)[0]
	if !row.IngestTime.Equal(epoch) || !row.PackageInstalledAt.Equal(epoch) {
		t.Fatalf("an absent instant reached the store as %s and %s", row.IngestTime, row.PackageInstalledAt)
	}
	if err := storable(row); err != nil {
		t.Fatalf("a record without reception is not storable: %v", err)
	}
}

// Left alone the driver folds such an instant into a wrapped-around one, so the
// record is refused to quarantine instead.
func TestAnInstantTheStoreCannotHoldIsNotStorable(t *testing.T) {
	for name, at := range map[string]time.Time{
		"after the store's window":  time.Date(3000, time.January, 1, 0, 0, 0, 0, time.UTC),
		"before the store's window": time.Date(1600, time.January, 1, 0, 0, 0, 0, time.UTC),
	} {
		t.Run(name, func(t *testing.T) {
			installed := packageItem("curl", "8.5.0")
			installed.GetPackage().InstalledAt = timestamppb.New(at)

			if err := storable(Project(record(inventoryv1.Kind_KIND_PACKAGE, installed))[0]); err == nil {
				t.Fatalf("%s was stored", at)
			}
		})
	}
}

func record(kind inventoryv1.Kind, items ...*inventoryv1.Item) *inventoryv1.Record {
	return &inventoryv1.Record{
		RecordId:      "inv-0000000001",
		SchemaVersion: 1,
		Kind:          kind,
		Mode:          inventoryv1.Mode_MODE_SNAPSHOT,
		CollectedAt:   timestamppb.New(collected),
		Origin: &eventv1.Origin{
			TenantId: "acme",
			AgentId:  "web-01",
			Host:     &eventv1.Host{Hostname: "node-1", Ip: "10.0.0.5", Os: "linux", Architecture: "amd64"},
		},
		Collection: &eventv1.Collection{Collector: "syscollector", Source: "dpkg", Sequence: 7},
		Reception: &eventv1.Reception{
			IngestTime: timestamppb.New(collected.Add(time.Second)),
			Gateway:    "ingest-gateway",
			BatchId:    "batch-1",
		},
		Items: items,
	}
}

func packageItem(name, version string) *inventoryv1.Item {
	return &inventoryv1.Item{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{
		Name:         name,
		Version:      version,
		Architecture: "amd64",
		Manager:      "dpkg",
	}}}
}

func filled(kind inventoryv1.Kind) *inventoryv1.Item {
	at := timestamppb.New(collected.Add(-time.Hour))
	switch kind {
	case inventoryv1.Kind_KIND_OPERATING_SYSTEM:
		return &inventoryv1.Item{Body: &inventoryv1.Item_OperatingSystem{
			OperatingSystem: &inventoryv1.OperatingSystem{
				Name: "Ubuntu", Version: "24.04", Build: "24.04.1",
				Platform: "ubuntu", Codename: "noble", Family: "debian",
			}}}
	case inventoryv1.Kind_KIND_KERNEL:
		return &inventoryv1.Item{Body: &inventoryv1.Item_Kernel{
			Kernel: &inventoryv1.Kernel{Name: "Linux", Release: "6.8.0-40", Version: "#40-Ubuntu", Architecture: "x86_64"}}}
	case inventoryv1.Kind_KIND_PACKAGE:
		return &inventoryv1.Item{Body: &inventoryv1.Item_Package{
			Package: &inventoryv1.Package{
				Name: "curl", Version: "8.5.0", Architecture: "amd64", Manager: "dpkg",
				Source: "curl", Vendor: "Ubuntu", SizeBytes: 1 << 18, InstalledAt: at,
			}}}
	case inventoryv1.Kind_KIND_SERVICE:
		return &inventoryv1.Item{Body: &inventoryv1.Item_Service{
			Service: &inventoryv1.Service{
				Name: "sshd", DisplayName: "OpenSSH", State: inventoryv1.Service_STATE_RUNNING,
				StartMode: "enabled", Path: "/usr/sbin/sshd",
			}}}
	case inventoryv1.Kind_KIND_NETWORK_INTERFACE:
		return &inventoryv1.Item{Body: &inventoryv1.Item_NetworkInterface{
			NetworkInterface: &inventoryv1.NetworkInterface{
				Name: "eth0", Mac: "02:42:ac:11:00:02", Addresses: []string{"10.0.0.5/24"},
				State: inventoryv1.NetworkInterface_STATE_UP, Mtu: 1500, Type: "ethernet",
			}}}
	case inventoryv1.Kind_KIND_USER:
		return &inventoryv1.Item{Body: &inventoryv1.Item_User{
			User: &inventoryv1.User{
				Name: "root", Uid: "0", Gid: "0", Home: "/root", Shell: "/bin/bash",
				Groups: []string{"root"}, LastLogin: at,
			}}}
	case inventoryv1.Kind_KIND_HARDWARE:
		return &inventoryv1.Item{Body: &inventoryv1.Item_Hardware{
			Hardware: &inventoryv1.Hardware{
				CpuName: "Xeon", CpuCores: 8, CpuMhz: 2400, MemoryTotalBytes: 1 << 34,
				Serial: "SN-1", Vendor: "Dell", Model: "R640",
			}}}
	default:
		return &inventoryv1.Item{Body: &inventoryv1.Item_Process{
			Process: &inventoryv1.Process{
				Pid: 4242, ParentPid: 1, Name: "sshd", Path: "/usr/sbin/sshd",
				CommandLine: "sshd: /usr/sbin/sshd -D", User: "root", StartedAt: at,
			}}}
	}
}
