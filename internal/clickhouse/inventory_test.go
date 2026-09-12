package clickhouse

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/inventorystore"
)

// NewInventoryStore runs the same check, so this drift never reaches a
// deployment.
func TestTheInventoryAdapterInsertsIntoTheColumnsTheSchemaCreates(t *testing.T) {
	for _, agreement := range []struct {
		table   string
		columns []string
	}{
		{inventoryTable, inventoryColumns},
		{scanTable, scanColumns},
	} {
		declared, err := declaredColumns(agreement.table)
		if err != nil {
			t.Fatalf("read the embedded schema: %v", err)
		}
		if slices.Equal(declared, agreement.columns) {
			continue
		}
		for _, column := range declared {
			if !slices.Contains(agreement.columns, column) {
				t.Errorf("%s creates %s and the adapter never writes to it", agreement.table, column)
			}
		}
		for _, column := range agreement.columns {
			if !slices.Contains(declared, column) {
				t.Errorf("the adapter writes to %s and %s has no such column", column, agreement.table)
			}
		}
		if len(declared) == len(agreement.columns) {
			t.Errorf("the columns of %s are the same set in a different order:\n schema: %v\nadapter: %v",
				agreement.table, declared, agreement.columns)
		}
	}
}

func TestEveryInventoryColumnIsGivenAValue(t *testing.T) {
	if err := inventoryAgreesWithSchema(); err != nil {
		t.Fatalf("the inventory adapter and the embedded schema disagree: %v", err)
	}
}

// A field added to the projection and forgotten in the insert would be written
// as the column beside it, silently, for every item an estate has.
func TestTheInventoryProjectionAndTheTableHaveTheSameWidth(t *testing.T) {
	if fields := reflect.TypeFor[inventorystore.Row]().NumField(); fields != len(inventoryColumns) {
		t.Errorf("an inventory row carries %d fields and %s takes %d columns",
			fields, inventoryTable, len(inventoryColumns))
	}
	if fields := reflect.TypeFor[inventorystore.Scan]().NumField(); fields != len(scanColumns) {
		t.Errorf("a scan carries %d fields and %s takes %d columns",
			fields, scanTable, len(scanColumns))
	}
}

// Absence is what the projection is for, and it is expressed by a line moving
// rather than by a row going away: a delete or a collapsing engine here would be
// a replay that cannot rebuild what it replaced.
func TestTheInventoryTablesAreReplacedAndNeverDeletedFrom(t *testing.T) {
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			lowered := strings.ToLower(statement)
			if !strings.Contains(lowered, inventoryTable) {
				continue
			}
			if strings.Contains(lowered, "delete from") || strings.Contains(lowered, "collapsingmergetree") {
				t.Errorf("%s retires an inventory item by removing a row", applied)
			}
		}
	}
}
