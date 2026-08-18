package main

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
)

// The structs are duplicated on purpose, so the risk is a field added on one
// side and forgotten here. Asserting nothing arrives zero catches that.

func TestAFetchedRecordCrossesWithEverythingOnIt(t *testing.T) {
	original := broker.Record{
		Partition: 7,
		Offset:    42,
		Key:       []byte("web-01"),
		Value:     []byte("an encoded event"),
	}

	converted := fetched([]broker.Record{original})
	if len(converted) != 1 {
		t.Fatalf("one record became %d", len(converted))
	}
	assertNothingIsZero(t, converted[0])

	if converted[0].Partition != original.Partition || converted[0].Offset != original.Offset {
		t.Errorf("the position changed: partition %d offset %d",
			converted[0].Partition, converted[0].Offset)
	}
	if !bytes.Equal(converted[0].Key, original.Key) || !bytes.Equal(converted[0].Value, original.Value) {
		t.Error("the record's bytes changed on the way across")
	}
}

func TestARefusedRecordCrossesWithEverythingOnIt(t *testing.T) {
	original := eventstore.Refused{
		Key:       []byte("web-01"),
		Value:     []byte("whatever arrived"),
		Reason:    eventstore.ReasonContractViolation,
		Detail:    "event_id is malformed",
		Partition: 3,
		Offset:    19,
	}

	converted := rejected([]eventstore.Refused{original})
	if len(converted) != 1 {
		t.Fatalf("one refusal became %d", len(converted))
	}
	assertNothingIsZero(t, converted[0])

	if converted[0].Reason != original.Reason || converted[0].Detail != original.Detail {
		t.Errorf("the refusal lost its reason: %q / %q", converted[0].Reason, converted[0].Detail)
	}
	if converted[0].Partition != original.Partition || converted[0].Offset != original.Offset {
		t.Error("a quarantined record has to say where it came from to be replayable")
	}
	if !bytes.Equal(converted[0].Value, original.Value) {
		t.Error("a quarantined record must carry the bytes that arrived, unchanged")
	}
}

func TestAnEmptyBatchDoesNotBecomeANilOne(t *testing.T) {
	if converted := fetched(nil); converted == nil || len(converted) != 0 {
		t.Errorf("an empty fetch converted to %v", converted)
	}
	if converted := rejected(nil); converted == nil || len(converted) != 0 {
		t.Errorf("an empty refusal list converted to %v", converted)
	}
}

func assertNothingIsZero(t *testing.T, converted any) {
	t.Helper()

	value := reflect.ValueOf(converted)
	for index := range value.NumField() {
		if value.Field(index).IsZero() {
			t.Errorf("%s did not survive the conversion", value.Type().Field(index).Name)
		}
	}
}
