package eventstore

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The store is a materialisation of what crossed the backbone, and this is what
// makes that true rather than said: everything an event carried comes back out
// of the projection unchanged, so a page of a hunt is the record itself.
func TestAnEventSurvivesTheRoundTrip(t *testing.T) {
	original := populated()

	restored := Restore(Project(original))
	if !proto.Equal(original, restored) {
		t.Errorf("the projection lost something:\n stored %v\nrestored %v", original, restored)
	}
}

func TestAnAbsentReceptionComesBackAbsent(t *testing.T) {
	original := populated()
	original.Reception = nil

	restored := Restore(Project(original))
	if restored.GetReception().GetIngestTime() != nil {
		t.Errorf("an event nobody received was given an ingest time of %v", restored.GetReception().GetIngestTime())
	}
	if !proto.Equal(original.GetOrigin(), restored.GetOrigin()) {
		t.Error("the rest of the record did not survive an absent reception")
	}
}

// A class the store wrote as nothing is nothing again, and a body belongs to the
// class that declares it: a row with no class carries no authentication.
func TestARowWithNoClassCarriesNoBody(t *testing.T) {
	row := Project(populated())
	row.EventClass = ""

	restored := Restore(row)
	if restored.GetAuthentication() != nil {
		t.Error("a row that named no class was restored with a body")
	}
	if restored.GetEventClass() != eventv1.EventClass_EVENT_CLASS_UNSPECIFIED {
		t.Errorf("the class came back as %v", restored.GetEventClass())
	}
}

func TestAPortIsRestoredAsTheContractWidth(t *testing.T) {
	original := populated()
	original.GetAuthentication().GetNetwork().GetSource().Port = 65535

	restored := Restore(Project(original))
	if port := restored.GetAuthentication().GetNetwork().GetSource().GetPort(); port != 65535 {
		t.Errorf("the widest port the store can hold came back as %d", port)
	}
}

func TestAnEnumIsRestoredFromTheNameTheStoreWrote(t *testing.T) {
	row := Project(populated())
	if row.AuthOutcome != "failure" {
		t.Fatalf("the store wrote the outcome as %q", row.AuthOutcome)
	}

	if outcome := Restore(row).GetAuthentication().GetOutcome(); outcome != eventv1.Outcome_OUTCOME_FAILURE {
		t.Errorf("the outcome came back as %v", outcome)
	}
}

func TestAnInstantKeepsItsMillisecond(t *testing.T) {
	at := time.Date(2026, time.August, 26, 10, 30, 0, 123_000_000, time.UTC)
	original := populated()
	original.Time = &eventv1.Timestamps{EventTime: timestamppb.New(at), ObservedTime: timestamppb.New(at)}

	restored := Restore(Project(original))
	if got := restored.GetTime().GetEventTime().AsTime(); !got.Equal(at) {
		t.Errorf("the instant came back as %s", got)
	}
}
