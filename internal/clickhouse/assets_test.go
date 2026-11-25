package clickhouse

import (
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventorystore"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func inventoryRecord(kind inventoryv1.Kind, mode inventoryv1.Mode, items ...*inventoryv1.Item) *inventoryv1.Record {
	return &inventoryv1.Record{
		RecordId: "inv-0000000001", SchemaVersion: 1, Kind: kind, Mode: mode,
		CollectedAt: timestamppb.New(time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)),
		Origin:      &eventv1.Origin{TenantId: "acme", AgentId: "web-01"},
		Items:       items,
	}
}

func installed(name, version string) *inventoryv1.Item {
	return &inventoryv1.Item{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{
		Name: name, Version: version, Architecture: "x86_64", Manager: "rpm",
	}}}
}

func account(name, uid string) *inventoryv1.Item {
	return &inventoryv1.Item{Body: &inventoryv1.Item_User{User: &inventoryv1.User{Name: name, Uid: uid}}}
}

func instanceOf(t *testing.T, row inventorystore.Row) []string {
	t.Helper()
	kind, known := inventory.KindOf(row.Kind)
	if !known {
		t.Fatalf("a row of kind %q", row.Kind)
	}
	var values []string
	for _, part := range instanceKeys[kind] {
		values = append(values, part.of(row))
	}
	return values
}

// After a delta two rows can say the same thing (ADR 43): a version an rpm
// snapshot showed alone is named without it, and the same version a delta
// shows is named with it. A reader lists the instance once, so both rows sort
// under one key.
func TestTwoRowsOfOneInstanceAreListedUnderOneKey(t *testing.T) {
	alone := inventorystore.Project(inventoryRecord(inventoryv1.Kind_KIND_PACKAGE, inventoryv1.Mode_MODE_SNAPSHOT, installed("openssl-libs", "1:3.5.1-3.el9")))[0]
	repeated := inventorystore.Project(inventoryRecord(inventoryv1.Kind_KIND_PACKAGE, inventoryv1.Mode_MODE_DELTA, installed("openssl-libs", "1:3.5.1-3.el9")))[0]
	if alone.ItemID == repeated.ItemID {
		t.Fatal("the fixture no longer stores the two as two rows, so it proves nothing")
	}
	if one, other := instanceOf(t, alone), instanceOf(t, repeated); !slices.Equal(one, other) {
		t.Errorf("one instance is listed under %q and %q", one, other)
	}
}

func TestTwoInstancesAreListedUnderTwoKeys(t *testing.T) {
	for name, record := range map[string]*inventoryv1.Record{
		"two kernels": inventoryRecord(inventoryv1.Kind_KIND_PACKAGE, inventoryv1.Mode_MODE_SNAPSHOT,
			installed("kernel-core", "5.14.0-687.60.1.el9_8"), installed("kernel-core", "5.14.0-687.61.1.el9_8")),
		"two accounts of uid 0": inventoryRecord(inventoryv1.Kind_KIND_USER, inventoryv1.Mode_MODE_SNAPSHOT,
			account("root", "0"), account("toor", "0")),
	} {
		rows := inventorystore.Project(record)
		if one, other := instanceOf(t, rows[0]), instanceOf(t, rows[1]); slices.Equal(one, other) {
			t.Errorf("%s are listed under one key %q", name, one)
		}
	}
}

func TestEveryKindIsListedUnderAKey(t *testing.T) {
	for value, name := range inventoryv1.Kind_name {
		kind := inventoryv1.Kind(value)
		if kind != inventoryv1.Kind_KIND_UNSPECIFIED && len(instanceKeys[kind]) == 0 {
			t.Errorf("an item of %s has no key to be listed and resumed by", name)
		}
	}
}
