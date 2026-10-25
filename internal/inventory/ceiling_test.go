package inventory_test

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

var (
	looked = time.Date(2026, time.October, 24, 12, 0, 0, 0, time.UTC)
	within = event.Policy{MaxClockSkew: time.Minute, MaxAge: 24 * time.Hour}
)

func processes(t *testing.T, size int) *inventoryv1.Record {
	t.Helper()
	snapshot := &inventoryv1.Record{
		RecordId:      "inv-0000000042",
		SchemaVersion: inventory.SchemaVersion,
		Kind:          inventoryv1.Kind_KIND_PROCESS,
		Mode:          inventoryv1.Mode_MODE_SNAPSHOT,
		CollectedAt:   timestamppb.New(looked),
		Origin:        &eventv1.Origin{TenantId: "acme", AgentId: "web-01"},
		Collection:    &eventv1.Collection{Collector: "processes"},
	}
	if !fixtures.Weigh(snapshot, size) {
		t.Fatalf("no process snapshot encodes to %d bytes", size)
	}
	return snapshot
}

func TestARecordIsAdmittedWhileItEncodesWithinTheCeiling(t *testing.T) {
	if err := inventory.Validate(processes(t, inventory.MaxRecordBytes), looked, within); err != nil {
		t.Fatalf("a record of %d bytes was refused: %v", inventory.MaxRecordBytes, err)
	}

	err := inventory.Validate(processes(t, inventory.MaxRecordBytes+1), looked, within)
	var violation *event.Violation
	if !errors.As(err, &violation) || violation.Field != "record" {
		t.Fatalf("a record one byte above the ceiling was answered %v, and the backbone would refuse it after the agent was told nothing", err)
	}
}

func TestTenThousandPackagesAsAnEstateReportsThemFitTheCeiling(t *testing.T) {
	widest := fixtures.PackageScan{At: looked, Packages: fixtures.DebianPackages(inventory.MaxItemsPerRecord)}.Record()
	if size := proto.Size(widest); size <= 1<<20 {
		t.Fatalf("the widest package list encodes to %d bytes, which a backbone carried before any ceiling was declared", size)
	}
	if err := inventory.Validate(widest, looked, within); err != nil {
		t.Fatalf("the item ceiling of packages as dpkg reports them was refused: %v", err)
	}
}
