package clickhouse

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/findingstore"
)

// NewFindingStore runs the same check, so this drift never reaches a
// deployment.
func TestTheFindingAdapterInsertsIntoTheColumnsTheSchemaCreates(t *testing.T) {
	if err := findingsAgreeWithSchema(); err != nil {
		t.Fatalf("the finding adapter and the embedded schema disagree: %v", err)
	}
	for _, agreement := range []struct {
		table   string
		columns []string
		fields  int
	}{
		{findingTable, findingColumns, reflect.TypeFor[findingstore.FindingRow]().NumField()},
		{findingAssessmentTable, findingAssessmentColumns, reflect.TypeFor[findingstore.AssessmentRow]().NumField()},
	} {
		if agreement.fields != len(agreement.columns) {
			t.Errorf("a row carries %d fields and %s takes %d columns", agreement.fields, agreement.table, len(agreement.columns))
		}
	}
}

// A finding is decided again every day it stays open, so what keeps the table
// from growing by a row per open finding per day is that its key names the
// episode and not the decision.
func TestAnOpenFindingDecidedAgainReplacesItsRowAndAFixDoesNot(t *testing.T) {
	var created string
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			if _, found := createTableBody(statement, findingTable); found {
				created = statement
			}
		}
	}
	if created == "" {
		t.Fatalf("no migration creates %s", findingTable)
	}
	key := sortingKeyOf(t, created)
	want := "tenant_id, agent_id, item_id, vulnerability_id, opened_at, state"
	if key != want {
		t.Fatalf("%s is ordered by (%s), want (%s)", findingTable, key, want)
	}
	for _, clock := range []string{"inventory_as_of", "intelligence_as_of", "decided_at"} {
		if slices.Contains(strings.Split(key, ", "), clock) {
			t.Errorf("%s is part of the key, so deciding an open finding again adds a row", clock)
		}
	}
}
