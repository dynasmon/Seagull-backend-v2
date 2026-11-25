package advisorystore

import (
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// A reader is handed the advisory the platform translated, so what the store
// keeps of a version comes back whole: its own row and one per package it
// names, every range with its events in the order the source wrote them.
func TestAStoredAdvisoryIsReadBackAsTheAdvisoryThatWasRead(t *testing.T) {
	withdrawn := advisory()
	withdrawn.Withdrawn = timestamppb.New(modified.Add(time.Hour))

	for name, original := range map[string]*vulnerabilityv1.Advisory{"in force": advisory(), "withdrawn": withdrawn} {
		projected := Project(advised(original))
		restored, err := Restore(projected.Advisories[0], projected.Affected)
		if err != nil || !proto.Equal(restored, original) {
			t.Errorf("an advisory %s was stored as\n%v\nand read back as\n%v (%v)", name, original, restored, err)
		}
	}
}

// Entries are placed by the position they were written at, whatever order the
// store hands them back in.
func TestAnAdvisoryIsReadBackWithItsPackagesInTheOrderTheSourceNamedThem(t *testing.T) {
	projected := Project(advised(advisory()))
	reversed := []AffectedRow{projected.Affected[1], projected.Affected[0]}
	restored, err := Restore(projected.Advisories[0], reversed)
	if err != nil || restored.GetAffected()[0].GetEcosystem() != "Debian:12" {
		t.Errorf("the packages were read back as %v (%v)", restored.GetAffected(), err)
	}
}

func TestARowWhoseEventsNameARangeItDoesNotHoldIsNotReadBack(t *testing.T) {
	projected := Project(advised(advisory()))
	broken := projected.Affected[0]
	broken.EventRanges = slices.Clone(broken.EventRanges)
	broken.EventRanges[0] = 7
	if restored, err := Restore(projected.Advisories[0], []AffectedRow{broken}); err == nil {
		t.Errorf("a row naming a range it does not hold was read back as %v", restored)
	}
}
