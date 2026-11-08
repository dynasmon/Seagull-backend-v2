package broker

import (
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

const (
	inventoryStream  = "security.inventory.raw"
	advisoriesStream = "security.advisories"
)

func readerOfTwo(ownership Ownership) *Consumer {
	return &Consumer{
		topics:    []string{inventoryStream, advisoriesStream},
		metrics:   NewConsumerMetrics(metrics.New("test")),
		ownership: ownership,
		assigned:  map[string]map[int32]struct{}{},
	}
}

func TestAReaderOfSeveralTopicsHoldsEachTopicsPartitionsApart(t *testing.T) {
	consumer := readerOfTwo(nil)

	consumer.took(map[string][]int32{inventoryStream: {0, 1, 2}, advisoriesStream: {0}})
	consumer.gave(map[string][]int32{inventoryStream: {1}})

	if got := consumer.Assigned(inventoryStream); len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Errorf("the reader holds %v of %s", got, inventoryStream)
	}
	if got := consumer.Assigned(advisoriesStream); len(got) != 1 || got[0] != 0 {
		t.Errorf("the reader holds %v of %s, and giving back a partition of another topic took one of these", got, advisoriesStream)
	}
}

func TestEveryMoveOfTheGroupAsksWhatTheReaderMayHold(t *testing.T) {
	var asked []map[string]int32
	consumer := readerOfTwo(func(held map[string]int32) error {
		asked = append(asked, maps.Clone(held))
		return nil
	})

	consumer.took(map[string][]int32{inventoryStream: {0, 1}})
	consumer.took(map[string][]int32{advisoriesStream: {0}})
	consumer.gave(map[string][]int32{inventoryStream: {0, 1}, advisoriesStream: {0}})

	want := []map[string]int32{
		{inventoryStream: 2, advisoriesStream: 0},
		{inventoryStream: 2, advisoriesStream: 1},
		{inventoryStream: 0, advisoriesStream: 0},
	}
	if len(asked) != len(want) {
		t.Fatalf("the reader was asked %d times: %v", len(asked), asked)
	}
	for index := range want {
		if !maps.Equal(asked[index], want[index]) {
			t.Errorf("move %d asked about %v, want %v", index, asked[index], want[index])
		}
	}
}

func TestAnAssignmentTheReaderMayNotHoldIsLatchedForTheLoopToStopOn(t *testing.T) {
	refusal := errors.New("another reader holds part of what this one has to read alone")
	consumer := readerOfTwo(func(held map[string]int32) error {
		if held[inventoryStream] != 6 || held[advisoriesStream] != 1 {
			return refusal
		}
		return nil
	})

	consumer.took(map[string][]int32{inventoryStream: {0, 1, 2, 3, 4, 5}, advisoriesStream: {0}})
	if err := consumer.refused(); err != nil {
		t.Fatalf("a reader holding everything was refused: %v", err)
	}
	consumer.gave(map[string][]int32{inventoryStream: {5}})
	if err := consumer.refused(); !errors.Is(err, refusal) {
		t.Fatalf("a reader left with part of what it reads alone kept going: %v", err)
	}
	consumer.took(map[string][]int32{inventoryStream: {5}})
	if err := consumer.refused(); !errors.Is(err, refusal) {
		t.Fatalf("a refusal was forgotten when the partition came back: %v", err)
	}
}

func TestAConsumerRefusesTopicsItCannotReadAsOne(t *testing.T) {
	for name, config := range map[string]ConsumerConfig{
		"no topic":             {Brokers: []string{"localhost:9092"}, Group: "g", MaxRecords: 1, Metrics: NewConsumerMetrics(metrics.New("test"))},
		"a topic twice":        {Brokers: []string{"localhost:9092"}, Topic: inventoryStream, Topics: []string{inventoryStream}, Group: "g", MaxRecords: 1, Metrics: NewConsumerMetrics(metrics.New("test"))},
		"an unnamed topic":     {Brokers: []string{"localhost:9092"}, Topics: []string{inventoryStream, ""}, Group: "g", MaxRecords: 1, Metrics: NewConsumerMetrics(metrics.New("test"))},
		"recovery from a list": {Brokers: []string{"localhost:9092"}, Topics: []string{inventoryStream}, Group: "g", MaxRecords: 1, Metrics: NewConsumerMetrics(metrics.New("test")), Recovery: func(int32) (time.Duration, error) { return 0, nil }},
		"recovery from two":    {Brokers: []string{"localhost:9092"}, Topics: []string{inventoryStream, advisoriesStream}, Group: "g", MaxRecords: 1, Metrics: NewConsumerMetrics(metrics.New("test")), Recovery: func(int32) (time.Duration, error) { return 0, nil }},
	} {
		if _, err := NewConsumer(config); err == nil {
			t.Errorf("%s: the consumer was built", name)
		}
	}
}
