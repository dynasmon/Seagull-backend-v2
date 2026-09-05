package broker

import (
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The declaration and the key are two statements of one fact, and a reader that
// admits a rule believes the declaration. This is what stops them drifting.
func TestTheDeclaredPartitioningIsTheKeyTheProducerWrites(t *testing.T) {
	record := &eventv1.Event{
		EventId:    "e-1",
		EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Origin:     &eventv1.Origin{AgentId: "web-01", TenantId: "acme"},
		Time:       &eventv1.Timestamps{EventTime: timestamppb.New(time.Now().UTC())},
	}

	records, err := encode("security.events.raw", []*eventv1.Event{record})
	if err != nil {
		t.Fatalf("encode an event: %v", err)
	}

	program, err := detection.Compile(detection.Rule{
		ID:          "partitioning.probe",
		Revision:    1,
		Name:        "What the stream is keyed by",
		Description: "Reads the declared partition fields out of an event the way a rule would.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.Predicate{
			Field:    "event_id",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue("e-1")},
		},
		Count:    detection.Count{AtLeast: 2, Within: time.Minute, GroupBy: PartitionedBy},
		Severity: detection.Low,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("group by what the stream is keyed by: %v", err)
	}

	group := program.Group(record)
	if len(group) != len(PartitionedBy) {
		t.Fatalf("the declared partitioning reads %d fields off an event", len(group))
	}

	keyed := ""
	for _, bound := range group {
		keyed += bound.Value
	}
	if keyed != string(records[0].Key) {
		t.Errorf("the stream is keyed by %q and %v reads %q", records[0].Key, PartitionedBy, keyed)
	}
}
