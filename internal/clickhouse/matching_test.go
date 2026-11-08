package clickhouse

import (
	"slices"
	"testing"
)

// VerifySchema runs the same check against the live store, so a read of a
// column no migration creates never reaches a deployment.
func TestTheMatcherReadsOnlyColumnsTheSchemaCreates(t *testing.T) {
	for table, columns := range matchingReads {
		declared, err := declaredColumns(table)
		if err != nil {
			t.Fatalf("read the embedded schema of %s: %v", table, err)
		}
		for _, column := range columns {
			if !slices.Contains(declared, column) {
				t.Errorf("the matcher reads %s.%s, which no migration creates", table, column)
			}
		}
	}
}

func TestAnEntryStoredInAShapeNoAdvisoryHasIsNotRebuilt(t *testing.T) {
	for name, entry := range map[string]struct {
		rangeTypes  []string
		eventRanges []uint32
		kinds       []string
		versions    []string
	}{
		"a range of a type the contract does not declare": {[]string{"bisect"}, nil, nil, nil},
		"events of a range that is not there":             {[]string{"ecosystem"}, []uint32{1}, []string{"introduced"}, []string{"0"}},
		"an event of no kind":                             {[]string{"ecosystem"}, []uint32{0}, []string{"skipped"}, []string{"0"}},
		"more events than versions":                       {[]string{"ecosystem"}, []uint32{0, 0}, []string{"introduced", "fixed"}, []string{"0"}},
	} {
		if rebuilt, err := affectedOf("AlmaLinux:9", "openssl-libs", entry.rangeTypes, entry.eventRanges, entry.kinds, entry.versions, nil, nil); err == nil {
			t.Errorf("%s: rebuilt as %v", name, rebuilt)
		}
	}

	rebuilt, err := affectedOf("AlmaLinux:9", "openssl-libs", []string{"ecosystem", "semver"}, []uint32{1, 0, 0},
		[]string{"limit", "introduced", "last_affected"}, []string{"2.0", "0", "1:3.0.7-27.el9"}, []string{"1:3.0.7-24.el9"}, nil)
	if err != nil {
		t.Fatalf("an entry of two ranges was refused: %v", err)
	}
	if len(rebuilt.GetRanges()) != 2 || len(rebuilt.GetRanges()[0].GetEvents()) != 2 || rebuilt.GetRanges()[1].GetEvents()[0].GetLimit() != "2.0" ||
		rebuilt.GetRanges()[0].GetEvents()[1].GetLastAffected() != "1:3.0.7-27.el9" {
		t.Fatalf("the events were rebuilt into %v", rebuilt.GetRanges())
	}
}
