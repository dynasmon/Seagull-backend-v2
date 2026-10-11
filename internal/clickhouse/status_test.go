package clickhouse

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/statusstore"
)

// NewStatusStore runs the same check, so this drift never reaches a
// deployment.
func TestTheStatusAdapterInsertsIntoTheColumnsTheSchemaCreates(t *testing.T) {
	if err := statusAgreesWithSchema(); err != nil {
		t.Fatalf("the status adapter and the embedded schema disagree: %v", err)
	}
	if fields := reflect.TypeFor[statusstore.Row]().NumField(); fields != len(statusColumns) {
		t.Errorf("a status row carries %d fields and %s takes %d columns", fields, statusTable, len(statusColumns))
	}
}

// Liveness is the platform's clock and nothing else: a table versioned by a
// time the agent writes would let a report claiming a later moment stand in for
// one the platform received later.
func TestTheNewestReportOfAnAgentIsTheOneThePlatformReceivedLast(t *testing.T) {
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			lowered := strings.ToLower(statement)
			if !strings.Contains(lowered, "create table if not exists "+statusTable) {
				continue
			}
			if !strings.Contains(lowered, "replacingmergetree(ingest_time)") || !strings.Contains(lowered, "order by (tenant_id, agent_id)") {
				t.Errorf("%s keeps the status of an agent otherwise than as its newest by ingest time:\n%s", applied, statement)
			}
			if strings.Contains(lowered, "partition by") {
				t.Errorf("%s partitions %s, so an agent would keep a row per partition that no merge reconciles", applied, statusTable)
			}
		}
	}
}
