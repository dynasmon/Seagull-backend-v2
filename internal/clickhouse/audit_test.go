package clickhouse

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/auditstore"
)

// NewAuditStore runs the same check, so this drift never reaches a deployment.
func TestTheAuditAdapterInsertsIntoTheColumnsTheSchemaCreates(t *testing.T) {
	if err := auditEntriesAgreeWithSchema(); err != nil {
		t.Fatalf("the audit adapter and the embedded schema disagree: %v", err)
	}
	if fields := reflect.TypeFor[auditstore.Row]().NumField(); fields != len(auditEntryColumns) {
		t.Errorf("an audit row carries %d fields and %s takes %d columns", fields, auditEntriesTable, len(auditEntryColumns))
	}
}

// A merge must never choose between two rows at one sequence, a TTL must never
// take an entry its chain still starts from, and a partition must never drop a
// stretch from the middle of a chain.
func TestTheAuditTrailIsKeptEveryRowAsItWasWritten(t *testing.T) {
	created := 0
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			lowered := strings.ToLower(statement)
			if !strings.Contains(lowered, "create table if not exists "+auditEntriesTable) {
				continue
			}
			created++
			for _, held := range []string{"engine = mergetree\n", "order by (chain, sequence)", "event_id type bloom_filter"} {
				if !strings.Contains(lowered, held) {
					t.Errorf("%s does not declare %q:\n%s", applied, held, statement)
				}
			}
			for _, refused := range []string{"replacingmergetree", "collapsingmergetree", "partition by", "ttl "} {
				if strings.Contains(lowered, refused) {
					t.Errorf("%s declares %q on %s", applied, refused, auditEntriesTable)
				}
			}
		}
	}
	if created != 1 {
		t.Errorf("%s is created by %d migrations", auditEntriesTable, created)
	}
}
