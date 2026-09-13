package clickhouse

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisorystore"
)

// NewAdvisoryStore runs the same check, so this drift never reaches a
// deployment.
func TestTheAdvisoryAdapterInsertsIntoTheColumnsTheSchemaCreates(t *testing.T) {
	for _, agreement := range []struct {
		table   string
		columns []string
	}{
		{advisoryTable, advisoryColumns},
		{affectedTable, affectedColumns},
		{feedSyncTable, feedSyncColumns},
	} {
		declared, err := declaredColumns(agreement.table)
		if err != nil {
			t.Fatalf("read the embedded schema: %v", err)
		}
		if !slices.Equal(declared, agreement.columns) {
			t.Errorf("%s creates %v and the adapter writes %v", agreement.table, declared, agreement.columns)
		}
	}
	if err := advisoriesAgreeWithSchema(); err != nil {
		t.Errorf("the advisory adapter and the embedded schema disagree: %v", err)
	}
}

// A field added to a row and forgotten in the insert would be written as the
// column beside it, silently, for every advisory the platform holds.
func TestTheAdvisoryRowsAndTheirTablesHaveTheSameWidth(t *testing.T) {
	for _, width := range []struct {
		row     reflect.Type
		table   string
		columns []string
	}{
		{reflect.TypeFor[advisorystore.AdvisoryRow](), advisoryTable, advisoryColumns},
		{reflect.TypeFor[advisorystore.AffectedRow](), affectedTable, affectedColumns},
		{reflect.TypeFor[advisorystore.SyncRow](), feedSyncTable, feedSyncColumns},
	} {
		if fields := width.row.NumField(); fields != len(width.columns) {
			t.Errorf("%s carries %d fields and %s takes %d columns", width.row.Name(), fields, width.table, len(width.columns))
		}
	}
}

// A version of an advisory is never removed: what was once concluded from it
// has to stay explicable, and a withdrawal is a newer version rather than a
// delete.
func TestTheAdvisoryTablesAreAppendedToAndNeverDeletedFrom(t *testing.T) {
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			lowered := " " + strings.ToLower(strings.Join(strings.Fields(statement), " ")) + " "
			if !strings.Contains(lowered, advisoryTable) && !strings.Contains(lowered, affectedTable) {
				continue
			}
			if strings.Contains(lowered, "delete") || strings.Contains(lowered, "collapsingmergetree") || strings.Contains(lowered, " ttl ") {
				t.Errorf("%s removes a version of an advisory", applied)
			}
		}
	}
}
