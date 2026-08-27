package clickhouse

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstore"
)

// NewDetectionStore runs the same check, so this drift never reaches a
// deployment.
func TestTheDetectionAdapterInsertsIntoTheColumnsTheSchemaCreates(t *testing.T) {
	declared, err := declaredColumns(detectionTable)
	if err != nil {
		t.Fatalf("read the embedded schema: %v", err)
	}

	if slices.Equal(declared, detectionColumns) {
		return
	}
	for _, column := range declared {
		if !slices.Contains(detectionColumns, column) {
			t.Errorf("%s creates %s and the adapter never writes to it", detectionTable, column)
		}
	}
	for _, column := range detectionColumns {
		if !slices.Contains(declared, column) {
			t.Errorf("the adapter writes to %s and %s has no such column", column, detectionTable)
		}
	}
	if len(declared) == len(detectionColumns) {
		t.Errorf("the columns are the same set in a different order:\n schema: %v\nadapter: %v",
			declared, detectionColumns)
	}
}

func TestEveryDetectionColumnIsGivenAValue(t *testing.T) {
	if err := detectionsAgreeWithSchema(); err != nil {
		t.Fatalf("the detection adapter and the embedded schema disagree: %v", err)
	}
}

// A field added to the projection and forgotten in the insert would be written
// as the column beside it, silently, for every detection.
func TestTheDetectionProjectionAndTheTableHaveTheSameWidth(t *testing.T) {
	fields := reflect.TypeFor[detectionstore.Row]().NumField()
	if fields != len(detectionColumns) {
		t.Errorf("a detection row carries %d fields and %s takes %d columns",
			fields, detectionTable, len(detectionColumns))
	}
}

// The two tables in this database are separate on purpose and must stay so: a
// detection is immutable and analytical, and an alert is mutable and owned.
// Nothing here may create one.
func TestThisDatabaseHoldsNoAlertTable(t *testing.T) {
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			if strings.Contains(strings.ToLower(statement), " alerts") {
				t.Errorf("%s creates an alerts table; an alert has a lifecycle and belongs in a relational store", applied)
			}
		}
	}
}
