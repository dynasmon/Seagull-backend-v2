package inventory

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

var collected = time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)

var window = event.Policy{MaxClockSkew: time.Minute, MaxAge: 24 * time.Hour}

func TestAWellFormedRecordIsAdmitted(t *testing.T) {
	if err := Validate(record(), collected, window); err != nil {
		t.Fatalf("a well formed record was refused: %v", err)
	}
}

func TestEveryKindPassesItsOwnValidation(t *testing.T) {
	for kind := range shapes {
		one := record()
		one.Kind = kind
		one.Items = []*inventoryv1.Item{filled(kind)}
		if err := Validate(one, collected, window); err != nil {
			t.Errorf("a %s record was refused: %v", KindName(kind), err)
		}
	}
}

func TestARecordIsRefusedField(t *testing.T) {
	for name, one := range map[string]struct {
		record *inventoryv1.Record
		field  string
	}{
		"no record id":     {mutate(func(r *inventoryv1.Record) { r.RecordId = "" }), "record_id"},
		"short record id":  {mutate(func(r *inventoryv1.Record) { r.RecordId = "abc" }), "record_id"},
		"malformed id":     {mutate(func(r *inventoryv1.Record) { r.RecordId = "not a record id" }), "record_id"},
		"schema version":   {mutate(func(r *inventoryv1.Record) { r.SchemaVersion = MaxSchemaVersion + 1 }), "schema_version"},
		"unspecified kind": {mutate(func(r *inventoryv1.Record) { r.Kind = inventoryv1.Kind_KIND_UNSPECIFIED }), "kind"},
		"undeclared kind":  {mutate(func(r *inventoryv1.Record) { r.Kind = inventoryv1.Kind(4242) }), "kind"},
		"unspecified mode": {mutate(func(r *inventoryv1.Record) { r.Mode = inventoryv1.Mode_MODE_UNSPECIFIED }), "mode"},
		"no collected at":  {mutate(func(r *inventoryv1.Record) { r.CollectedAt = nil }), "collected_at"},
		"no agent":         {mutate(func(r *inventoryv1.Record) { r.Origin.AgentId = "" }), "origin.agent_id"},
		"no tenant":        {mutate(func(r *inventoryv1.Record) { r.Origin.TenantId = "" }), "origin.tenant_id"},
		"no collector":     {mutate(func(r *inventoryv1.Record) { r.Collection.Collector = "" }), "collection.collector"},
	} {
		t.Run(name, func(t *testing.T) {
			err := Validate(one.record, collected, window)
			if err == nil {
				t.Fatal("the record was admitted")
			}
			var violation *event.Violation
			if !errors.As(err, &violation) {
				t.Fatalf("the refusal names no field: %v", err)
			}
			if violation.Field != one.field {
				t.Errorf("the refusal names %s and the fault is in %s", violation.Field, one.field)
			}
		})
	}
}

// The distinction the whole projection rests on: a snapshot that names nothing
// says the asset has nothing of that kind, which is a fact worth admitting; a
// delta that names nothing says nothing at all.
func TestAnEmptySnapshotIsAdmittedAndAnEmptyDeltaIsNot(t *testing.T) {
	empty := mutate(func(r *inventoryv1.Record) { r.Items = nil })
	if err := Validate(empty, collected, window); err != nil {
		t.Errorf("an empty snapshot was refused: %v", err)
	}

	delta := mutate(func(r *inventoryv1.Record) {
		r.Items = nil
		r.Mode = inventoryv1.Mode_MODE_DELTA
	})
	if err := Validate(delta, collected, window); err == nil {
		t.Error("an empty delta was admitted, so a record that states nothing reached the backbone")
	}
}

func TestAnItemMustCarryTheBodyTheKindNames(t *testing.T) {
	mismatched := mutate(func(r *inventoryv1.Record) {
		r.Kind = inventoryv1.Kind_KIND_PACKAGE
		r.Items = []*inventoryv1.Item{filled(inventoryv1.Kind_KIND_SERVICE)}
	})
	if err := Validate(mismatched, collected, window); err == nil {
		t.Error("a package record carrying a service was admitted")
	}

	empty := mutate(func(r *inventoryv1.Record) { r.Items = []*inventoryv1.Item{{}} })
	if err := Validate(empty, collected, window); err == nil {
		t.Error("an item carrying no body at all was admitted")
	}
}

func TestASingletonKindCarriesAtMostOneItem(t *testing.T) {
	two := mutate(func(r *inventoryv1.Record) {
		r.Kind = inventoryv1.Kind_KIND_KERNEL
		r.Items = []*inventoryv1.Item{
			filled(inventoryv1.Kind_KIND_KERNEL),
			filled(inventoryv1.Kind_KIND_KERNEL),
		}
	})
	if err := Validate(two, collected, window); err == nil {
		t.Error("an asset was allowed to report two kernels, which would fold into one row")
	}
}

func TestABatchCannotBuyMemoryWithItemCounts(t *testing.T) {
	crowded := mutate(func(r *inventoryv1.Record) {
		r.Items = make([]*inventoryv1.Item, MaxItemsPerRecord+1)
		for index := range r.Items {
			r.Items[index] = filled(inventoryv1.Kind_KIND_PACKAGE)
		}
	})
	if err := Validate(crowded, collected, window); err == nil {
		t.Errorf("a record carrying more than %d items was admitted", MaxItemsPerRecord)
	}
}

// A replay reprocesses what it exists to reprocess, so the contract rules hold
// for a record the admission window would refuse.
func TestTheAdmissionWindowIsNotPartOfTheContract(t *testing.T) {
	old := mutate(func(r *inventoryv1.Record) {
		r.CollectedAt = timestamppb.New(collected.Add(-48 * time.Hour))
	})
	if err := ValidateContract(old); err != nil {
		t.Errorf("a replayed record was refused by the contract: %v", err)
	}
	if err := Validate(old, collected, window); err == nil {
		t.Error("a record older than the admission window was admitted")
	}

	ahead := mutate(func(r *inventoryv1.Record) {
		r.CollectedAt = timestamppb.New(collected.Add(time.Hour))
	})
	if err := Validate(ahead, collected, window); err == nil {
		t.Error("a record ahead of the platform clock was admitted")
	}
}

// A collector that could not read a state has observed that it could not, and
// that is worth keeping; a number no build declares would be read back as
// unspecified and would lose what it said.
func TestAnUnreadStateIsAdmittedAndAnUndeclaredOneIsNot(t *testing.T) {
	unread := mutate(func(r *inventoryv1.Record) {
		r.Kind = inventoryv1.Kind_KIND_SERVICE
		r.Items = []*inventoryv1.Item{{Body: &inventoryv1.Item_Service{
			Service: &inventoryv1.Service{Name: "sshd"},
		}}}
	})
	if err := Validate(unread, collected, window); err != nil {
		t.Errorf("a service whose state the collector could not read was refused: %v", err)
	}

	invented := mutate(func(r *inventoryv1.Record) {
		r.Kind = inventoryv1.Kind_KIND_SERVICE
		r.Items = []*inventoryv1.Item{{Body: &inventoryv1.Item_Service{
			Service: &inventoryv1.Service{Name: "sshd", State: inventoryv1.Service_State(99)},
		}}}
	})
	if err := Validate(invented, collected, window); err == nil {
		t.Error("a service state no build declares was admitted")
	}
}

func TestAnInterfaceHoldsAddressesAndPrefixes(t *testing.T) {
	for name, addresses := range map[string][]string{
		"an address":  {"10.0.0.5"},
		"a prefix":    {"10.0.0.5/24"},
		"both stacks": {"10.0.0.5/24", "fd00::1/64"},
	} {
		one := interfaceRecord(addresses)
		if err := Validate(one, collected, window); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}

	for name, addresses := range map[string][]string{
		"a hostname":   {"gateway.internal"},
		"nothing":      {""},
		"a bad prefix": {"10.0.0.5/99"},
	} {
		one := interfaceRecord(addresses)
		if err := Validate(one, collected, window); err == nil {
			t.Errorf("%s was admitted as an interface address", name)
		}
	}
}

func TestALongFieldIsRefused(t *testing.T) {
	long := mutate(func(r *inventoryv1.Record) {
		r.Items = []*inventoryv1.Item{packageItem(strings.Repeat("p", MaxNameLength+1), "1", "amd64", "dpkg")}
	})
	if err := Validate(long, collected, window); err == nil {
		t.Errorf("a package name longer than %d bytes was admitted", MaxNameLength)
	}
}

func interfaceRecord(addresses []string) *inventoryv1.Record {
	return mutate(func(r *inventoryv1.Record) {
		r.Kind = inventoryv1.Kind_KIND_NETWORK_INTERFACE
		r.Items = []*inventoryv1.Item{{Body: &inventoryv1.Item_NetworkInterface{
			NetworkInterface: &inventoryv1.NetworkInterface{Name: "eth0", Addresses: addresses},
		}}}
	})
}

func record() *inventoryv1.Record {
	return &inventoryv1.Record{
		RecordId:      "inv-0000000001",
		SchemaVersion: SchemaVersion,
		Kind:          inventoryv1.Kind_KIND_PACKAGE,
		Mode:          inventoryv1.Mode_MODE_SNAPSHOT,
		CollectedAt:   timestamppb.New(collected),
		Origin: &eventv1.Origin{
			TenantId: "default",
			AgentId:  "agent-1",
			Host:     &eventv1.Host{Hostname: "node-1", Ip: "10.0.0.5", Os: "linux", Architecture: "amd64"},
		},
		Collection: &eventv1.Collection{Collector: "syscollector", Source: "dpkg", Sequence: 7},
		Items:      []*inventoryv1.Item{packageItem("curl", "8.5.0", "amd64", "dpkg")},
	}
}

func mutate(change func(*inventoryv1.Record)) *inventoryv1.Record {
	one := record()
	change(one)
	return one
}
