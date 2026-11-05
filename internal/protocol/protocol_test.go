package protocol_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

func described(records uint32) *platformv1.Descriptor {
	held := protocol.Descriptor(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	held.Streams = []*platformv1.Stream{{Route: "POST /v1/events", MaxRecordsPerBatch: records}}
	return held
}

func TestADescriptorIsTaggedByWhatItDescribesAndNeverByWhenItWasAsked(t *testing.T) {
	first, err := protocol.Tag(described(1000))
	if err != nil {
		t.Fatal(err)
	}

	later := described(1000)
	later.ServerTime = timestamppb.New(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	unasked := described(1000)
	unasked.ServerTime = nil
	for name, held := range map[string]*platformv1.Descriptor{"asked later": later, "never asked": unasked} {
		if tag, err := protocol.Tag(held); err != nil || tag != first {
			t.Errorf("the same descriptor %s is tagged %q (%v), and first %q", name, tag, err, first)
		}
	}

	if changed, err := protocol.Tag(described(999)); err != nil || changed == first {
		t.Errorf("a descriptor whose stream admits fewer records is tagged %q (%v), as the one before", changed, err)
	}
	if len(first) != 34 || first[0] != '"' || first[len(first)-1] != '"' {
		t.Errorf("the tag %s is not a quoted entity tag", first)
	}
}

func TestADescriptorIsAnsweredAsItStandsAtTheMomentItIsAsked(t *testing.T) {
	held := described(1000)
	asked := time.Date(2026, 11, 4, 15, 30, 0, 0, time.FixedZone("BRT", -3*60*60))

	encoded, err := protocol.Answer(held, asked)
	if err != nil {
		t.Fatal(err)
	}
	var answered platformv1.Descriptor
	if err := proto.Unmarshal(encoded, &answered); err != nil {
		t.Fatal(err)
	}
	if !answered.GetServerTime().AsTime().Equal(asked) || len(answered.GetStreams()) != 1 {
		t.Fatalf("the descriptor was answered at %v with %d streams", answered.GetServerTime().AsTime(), len(answered.GetStreams()))
	}
	if !held.GetServerTime().AsTime().Equal(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("answering a descriptor changed the one the listener holds")
	}
}
