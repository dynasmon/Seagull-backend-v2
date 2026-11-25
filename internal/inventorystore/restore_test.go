package inventorystore

import (
	"testing"

	"google.golang.org/protobuf/proto"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// A reader is handed the item the collector reported, so what the store keeps
// of it has to come back whole: every field of every kind, through its row.
func TestAStoredItemIsReadBackAsTheItemThatWasReported(t *testing.T) {
	for kind := range groups {
		reported := filled(kind)
		body := reported.ProtoReflect().WhichOneof(reported.ProtoReflect().Descriptor().Oneofs().ByName("body"))
		every := reported.ProtoReflect().Get(body).Message()
		fields := every.Descriptor().Fields()
		for index := range fields.Len() {
			if !every.Has(fields.Get(index)) {
				t.Fatalf("the %s fixture leaves %s unset, so reading it back proves nothing about it", kind, fields.Get(index).Name())
			}
		}

		row := Project(record(kind, reported))[0]
		if restored := Restore(row); !proto.Equal(restored, reported) {
			t.Errorf("%s was stored as\n%v\nand read back as\n%v", kind, reported, restored)
		}
	}
}

// An instant nobody gave is stored as the epoch, and it is read back as absent
// rather than as a package installed in 1970.
func TestAnInstantNobodyGaveIsReadBackAsAbsent(t *testing.T) {
	row := Project(record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.5.0")))[0]
	if at := Restore(row).GetPackage().GetInstalledAt(); at != nil {
		t.Errorf("a package nobody said was installed at any time was read back as installed at %v", at.AsTime())
	}
}

func TestAnUnspecifiedStateIsReadBackAsUnspecified(t *testing.T) {
	quiet := &inventoryv1.Item{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "cron"}}}
	row := Project(record(inventoryv1.Kind_KIND_SERVICE, quiet))[0]
	if state := Restore(row).GetService().GetState(); state != inventoryv1.Service_STATE_UNSPECIFIED {
		t.Errorf("a service whose state nobody gave was read back as %s", state)
	}
}

// The host a record was sent from is read back from any of its rows.
func TestTheHostARecordNamedIsReadBackFromItsRow(t *testing.T) {
	row := Project(record(inventoryv1.Kind_KIND_KERNEL, filled(inventoryv1.Kind_KIND_KERNEL)))[0]
	want := &eventv1.Host{Hostname: "node-1", Ip: "10.0.0.5", Os: "linux", Architecture: "amd64"}
	if host := HostOf(row); !proto.Equal(host, want) {
		t.Errorf("the host was read back as %v", host)
	}
}
