package main

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
)

// The structs are duplicated on purpose, so the risk is a field added on one
// side and forgotten here. Asserting nothing arrives zero catches that.

func TestAFetchedRecordReachesTheEngineWithEverythingOnIt(t *testing.T) {
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

	value := reflect.ValueOf(converted[0])
	for index := range value.NumField() {
		if value.Field(index).IsZero() {
			t.Errorf("%s did not survive the conversion", value.Type().Field(index).Name)
		}
	}

	if converted[0].Partition != original.Partition || converted[0].Offset != original.Offset {
		t.Errorf("the position changed: partition %d offset %d",
			converted[0].Partition, converted[0].Offset)
	}
	if !bytes.Equal(converted[0].Key, original.Key) || !bytes.Equal(converted[0].Value, original.Value) {
		t.Error("the record's bytes changed on the way across")
	}
}

// The engine reports the size of every batch it is handed, so an empty fetch has
// to arrive as an empty batch rather than as nothing.
func TestAnEmptyFetchDoesNotBecomeANilBatch(t *testing.T) {
	if converted := fetched(nil); converted == nil || len(converted) != 0 {
		t.Errorf("an empty fetch converted to %v", converted)
	}
}
