package clickhouse

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
)

// NewStore runs the same check, so this drift never reaches a deployment.
func TestTheAdapterInsertsIntoTheColumnsTheSchemaCreates(t *testing.T) {
	declared, err := declaredColumns(table)
	if err != nil {
		t.Fatalf("read the embedded schema: %v", err)
	}

	if slices.Equal(declared, storedColumns) {
		return
	}
	for _, column := range declared {
		if !slices.Contains(storedColumns, column) {
			t.Errorf("%s creates %s and the adapter never writes to it", table, column)
		}
	}
	for _, column := range storedColumns {
		if !slices.Contains(declared, column) {
			t.Errorf("the adapter writes to %s and %s has no such column", column, table)
		}
	}
	if len(declared) == len(storedColumns) {
		t.Errorf("the columns are the same set in a different order:\n schema: %v\nadapter: %v",
			declared, storedColumns)
	}
}

func TestEveryColumnIsGivenAValue(t *testing.T) {
	if got, want := len(values(eventstore.Row{})), len(storedColumns); got != want {
		t.Fatalf("the adapter names %d columns and supplies %d values", want, got)
	}
}

// A field added to the projection and forgotten here would be filled, carried,
// and never written. Nothing else compares the two widths.
func TestTheProjectionAndTheTableHaveTheSameWidth(t *testing.T) {
	fields := reflect.TypeOf(eventstore.Row{}).NumField()
	if fields != len(storedColumns) {
		t.Fatalf("the projection carries %d fields and the table holds %d columns",
			fields, len(storedColumns))
	}
}

func TestTheEmbeddedSchemaIsOrderedAndComplete(t *testing.T) {
	if len(migrations) == 0 {
		t.Fatal("no migration was embedded")
	}
	for index, applied := range migrations {
		if applied.version == 0 {
			t.Errorf("%s has no version", applied)
		}
		if len(applied.statements) == 0 {
			t.Errorf("%s carries no statement", applied)
		}
		if index > 0 && applied.version <= migrations[index-1].version {
			t.Errorf("%s does not come after %s", applied, migrations[index-1])
		}
	}
}

// An interrupted run applies every statement again, so a migration that is not
// idempotent turns a restart into an outage.
func TestEveryMigrationIsIdempotent(t *testing.T) {
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			upper := strings.ToUpper(statement)
			switch {
			case strings.HasPrefix(upper, "CREATE TABLE IF NOT EXISTS"),
				strings.HasPrefix(upper, "ALTER TABLE"),
				strings.HasPrefix(upper, "CREATE VIEW IF NOT EXISTS"),
				strings.HasPrefix(upper, "CREATE MATERIALIZED VIEW IF NOT EXISTS"):
			default:
				t.Errorf("%s runs a statement that cannot be applied twice: %.60s...", applied, statement)
			}
		}
	}
}

func TestAMigrationFilenameHasToSayWhatItIsAndWhen(t *testing.T) {
	for _, filename := range []string{
		"security_events.sql",
		"0000_nothing.sql",
		"one_security_events.sql",
		"0002_.sql",
	} {
		if _, _, err := describe(filename); err == nil {
			t.Errorf("%s was accepted as a migration name", filename)
		}
	}

	version, name, err := describe("0007_add_process_events.sql")
	if err != nil {
		t.Fatalf("describe a well formed name: %v", err)
	}
	if version != 7 || name != "add_process_events" {
		t.Fatalf("read version %d name %q", version, name)
	}
}

func TestTheLedgerIsNotOneOfTheThingsItRecords(t *testing.T) {
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			if strings.Contains(strings.ToUpper(statement), strings.ToUpper(ledger)) {
				t.Fatalf("%s touches %s, which records what has been applied", applied, ledger)
			}
		}
	}
}
