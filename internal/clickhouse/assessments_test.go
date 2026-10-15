package clickhouse

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/assessmentstore"
)

// NewAssessmentStore runs the same check, so this drift never reaches a
// deployment.
func TestTheAssessmentAdapterInsertsIntoTheColumnsTheSchemaCreates(t *testing.T) {
	if err := assessmentsAgreeWithSchema(); err != nil {
		t.Fatalf("the assessment adapter and the embedded schema disagree: %v", err)
	}
	if fields := reflect.TypeFor[assessmentstore.Row]().NumField(); fields != len(assessmentColumns) {
		t.Errorf("an assessment row carries %d fields and %s takes %d columns", fields, assessmentTable, len(assessmentColumns))
	}
}

// Every assessment is a row of its own and the same one published twice is
// one row: a key without the assessment would fold the history of a host into
// its newest posture, and a version taken from the agent's clock would let a
// copy claiming a later moment replace the one the platform received.
func TestEveryAssessmentIsKeptOnceAndVersionedByThePlatformClock(t *testing.T) {
	found := false
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			lowered := strings.ToLower(statement)
			if !strings.Contains(lowered, "create table if not exists "+assessmentTable) {
				continue
			}
			found = true
			if !strings.Contains(lowered, "replacingmergetree(ingest_time)") ||
				!strings.Contains(lowered, "order by (tenant_id, agent_id, assessed_at, assessment_id)") {
				t.Errorf("%s keeps the assessments of an agent otherwise than once each, versioned by ingest time:\n%s", applied, statement)
			}
		}
	}
	if !found {
		t.Fatalf("no migration creates %s", assessmentTable)
	}
}
