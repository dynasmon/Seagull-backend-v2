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

func TestLaterMigrationsProduceTheFinalColumnOrder(t *testing.T) {
	history := []migration{
		{
			version: 1,
			name:    "security_events",
			statements: []string{`CREATE TABLE IF NOT EXISTS security_events
(
    event_id String,
    obsolete String
)
ENGINE = MergeTree
ORDER BY event_id`},
		},
		{
			version: 2,
			name:    "add_process_fields",
			statements: []string{`ALTER TABLE security_events
ADD COLUMN IF NOT EXISTS process_name String AFTER event_id,
ADD COLUMN IF NOT EXISTS process_identity Tuple(UInt32, UInt32) AFTER process_name,
ADD COLUMN IF NOT EXISTS tenant_id String FIRST,
ADD COLUMN IF NOT EXISTS process_path String`},
		},
		{
			version: 3,
			name:    "refine_process_fields",
			statements: []string{`ALTER TABLE security_events
RENAME COLUMN IF EXISTS process_identity TO process_id,
DROP COLUMN IF EXISTS obsolete`},
		},
	}

	got, err := declaredColumnsIn(history, table)
	if err != nil {
		t.Fatalf("build the final schema: %v", err)
	}
	want := []string{"tenant_id", "event_id", "process_name", "process_id", "process_path"}
	if !slices.Equal(got, want) {
		t.Fatalf("the final columns are %v, want %v", got, want)
	}
}

func TestEveryColumnIsGivenAValue(t *testing.T) {
	if got, want := len(values(eventstore.Row{})), len(storedColumns); got != want {
		t.Fatalf("the adapter names %d columns and supplies %d values", want, got)
	}
}

// Catch projected fields that are never written.
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

// Interrupted migrations replay statements before recording the ledger row.
func TestEveryMigrationIsIdempotent(t *testing.T) {
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			if !isIdempotent(statement) {
				t.Errorf("%s runs a statement that cannot be applied twice: %.60s...", applied, statement)
			}
		}
	}
}

func TestAlterColumnActionsNeedTheirOwnIdempotencyGuard(t *testing.T) {
	cases := []struct {
		name      string
		statement string
		want      bool
	}{
		{"guarded add", "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS process_name String", true},
		{"unguarded add", "ALTER TABLE security_events ADD COLUMN process_name String", false},
		{"guarded drop", "ALTER TABLE security_events DROP COLUMN IF EXISTS process_name", true},
		{"unguarded drop", "ALTER TABLE security_events DROP COLUMN process_name", false},
		{"guarded rename", "ALTER TABLE security_events RENAME COLUMN IF EXISTS process_name TO image_name", true},
		{"unguarded rename", "ALTER TABLE security_events RENAME COLUMN process_name TO image_name", false},
		{
			"one unguarded action",
			"ALTER TABLE security_events ADD COLUMN IF NOT EXISTS process_name String, ADD COLUMN process_id UInt32",
			false,
		},
		{"unsupported mutation", "ALTER TABLE security_events UPDATE process_id = 0 WHERE process_id < 0", false},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := isIdempotent(test.statement); got != test.want {
				t.Fatalf("isIdempotent returned %t, want %t", got, test.want)
			}
		})
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
