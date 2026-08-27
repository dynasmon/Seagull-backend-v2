package detectionstore

import (
	"testing"

	"google.golang.org/protobuf/proto"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

// The finding an analyst reads back is the record the engine published, evidence
// included: five parallel columns are one list again, in the order they were
// written.
func TestADetectionSurvivesTheRoundTrip(t *testing.T) {
	original := populated()

	restored := Restore(Project(original))
	if !proto.Equal(original, restored) {
		t.Errorf("the projection lost something:\n stored %v\nrestored %v", original, restored)
	}
}

func TestADetectionWithoutEvidenceComesBackWithout(t *testing.T) {
	original := populated()
	original.Evidence = nil

	restored := Restore(Project(original))
	if len(restored.GetEvidence()) != 0 {
		t.Errorf("evidence was invented: %v", restored.GetEvidence())
	}
}

// A store that answered with columns of different lengths lost part of a row,
// and the reader reads as far as all five reach rather than inventing the rest.
func TestEvidenceIsReadOnlyAsFarAsEveryColumnReaches(t *testing.T) {
	row := Project(populated())
	row.EvidenceHeld = row.EvidenceHeld[:1]

	if seen := Restore(row).GetEvidence(); len(seen) != 1 {
		t.Errorf("a short column produced %d entries of evidence", len(seen))
	}
}

func TestASeverityIsRestoredFromTheNameTheStoreWrote(t *testing.T) {
	row := Project(populated())
	if row.Severity != "medium" {
		t.Fatalf("the store wrote the severity as %q", row.Severity)
	}

	if severity := Restore(row).GetSeverity(); severity != detectionv1.Severity_SEVERITY_MEDIUM {
		t.Errorf("the severity came back as %v", severity)
	}
}

func TestADetectionWithNoSeverityComesBackUnspecified(t *testing.T) {
	row := Project(populated())
	row.Severity = ""

	if severity := Restore(row).GetSeverity(); severity != detectionv1.Severity_SEVERITY_UNSPECIFIED {
		t.Errorf("a detection nobody graded came back as %v", severity)
	}
}
