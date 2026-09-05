package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

const stream = "security.events.raw"

func listed(offsets map[int32]int64) kadm.ListedOffsets {
	partitions := make(map[int32]kadm.ListedOffset, len(offsets))
	for partition, offset := range offsets {
		partitions[partition] = kadm.ListedOffset{Topic: stream, Partition: partition, Offset: offset}
	}
	return kadm.ListedOffsets{stream: partitions}
}

func reader(t *testing.T, recovery Recovery, ends, after kadm.ListedOffsets) *Consumer {
	t.Helper()

	return &Consumer{
		topic:      stream,
		metrics:    NewConsumerMetrics(metrics.New("test")),
		endOffsets: staticEndOffsets{offsets: ends, after: after},
		recovery:   recovery,
		assigned:   map[int32]struct{}{0: {}, 1: {}},
	}
}

func committed(offsets map[int32]int64) map[string]map[int32]kgo.Offset {
	partitions := make(map[int32]kgo.Offset, len(offsets))
	for partition, offset := range offsets {
		partitions[partition] = kgo.NewOffset().At(offset)
	}
	return map[string]map[int32]kgo.Offset{stream: partitions}
}

func at(t *testing.T, offsets map[string]map[int32]kgo.Offset, partition int32) int64 {
	t.Helper()

	position, held := offsets[stream][partition]
	if !held {
		t.Fatalf("partition %d is not in the assignment", partition)
	}
	return position.EpochOffset().Offset
}

func TestAnAssignmentIsReadBackFarEnoughToRebuildWhatTheWindowHeld(t *testing.T) {
	consumer := reader(t,
		func(int32) (time.Duration, error) { return 10 * time.Minute, nil },
		listed(map[int32]int64{0: 900, 1: 900}),
		listed(map[int32]int64{0: 400, 1: 550}),
	)

	rebuilt, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 800, 1: 700}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 400 {
		t.Errorf("partition 0 resumes at %d, want the first record inside the window", got)
	}
	if got := at(t, rebuilt, 1); got != 550 {
		t.Errorf("partition 1 resumes at %d, want the first record inside the window", got)
	}
}

// Moving a lagging reader forward would step over telemetry nobody decided.
func TestAReaderBehindTheWindowIsNeverMovedForwardToMeetIt(t *testing.T) {
	consumer := reader(t,
		func(int32) (time.Duration, error) { return time.Hour, nil },
		listed(map[int32]int64{0: 9000}),
		listed(map[int32]int64{0: 8000}),
	)

	rebuilt, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 120}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 120 {
		t.Errorf("a lagging reader was moved to %d and would have skipped everything before it", got)
	}
}

func TestAReaderThatRemembersNothingIsLeftWhereTheGroupPutIt(t *testing.T) {
	unrecovered := reader(t, nil, listed(map[int32]int64{0: 900}), listed(map[int32]int64{0: 100}))
	rebuilt, err := unrecovered.rebuild(context.Background(), committed(map[int32]int64{0: 800}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 800 {
		t.Errorf("a reader with nothing to rebuild resumed at %d", got)
	}

	stateless := reader(t,
		func(int32) (time.Duration, error) { return 0, nil },
		listed(map[int32]int64{0: 900}),
		listed(map[int32]int64{0: 100}),
	)
	rebuilt, err = stateless.rebuild(context.Background(), committed(map[int32]int64{0: 800}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 800 {
		t.Errorf("a ruleset that remembers nothing read back to %d", got)
	}
}

func TestAPartitionThisGroupHasNeverCommittedIsLeftAtItsResetPosition(t *testing.T) {
	consumer := reader(t,
		func(int32) (time.Duration, error) { return time.Hour, nil },
		listed(map[int32]int64{0: 900}),
		listed(map[int32]int64{0: 100}),
	)

	rebuilt, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: -1}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != -1 {
		t.Errorf("an uncommitted partition was moved to %d", got)
	}
}

func TestAnAssignmentTheReaderRefusesStopsItRatherThanRejoining(t *testing.T) {
	refusal := errors.New("this reader holds 6 of 12 partitions and a rule counts across agents")
	consumer := reader(t,
		func(int32) (time.Duration, error) { return 0, refusal },
		listed(map[int32]int64{0: 900}),
		nil,
	)

	if _, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 800})); !errors.Is(err, refusal) {
		t.Fatalf("the assignment was accepted: %v", err)
	}
	if err := consumer.refused(); !errors.Is(err, refusal) {
		t.Fatalf("the refusal did not reach the caller waiting on Consume: %v", err)
	}
}

// Failing open here would start the reader with an empty window and no way to
// know it, which is the silent false negative this whole path exists to remove.
func TestABackboneThatWillNotSayWhereTheWindowStartsStopsTheReader(t *testing.T) {
	unavailable := errors.New("broker unavailable")
	consumer := &Consumer{
		topic:      stream,
		metrics:    NewConsumerMetrics(metrics.New("test")),
		endOffsets: staticEndOffsets{err: unavailable},
		recovery:   func(int32) (time.Duration, error) { return time.Hour, nil },
		assigned:   map[int32]struct{}{0: {}},
	}

	if _, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 800})); !errors.Is(err, unavailable) {
		t.Fatalf("an unreadable backbone was treated as nothing to rebuild: %v", err)
	}
	if err := consumer.refused(); !errors.Is(err, unavailable) {
		t.Fatalf("the refusal did not reach the caller waiting on Consume: %v", err)
	}
}

func TestWhatTheReaderHoldsFollowsTheGroupMovingPartitionsAround(t *testing.T) {
	consumer := &Consumer{
		topic:    stream,
		metrics:  NewConsumerMetrics(metrics.New("test")),
		assigned: map[int32]struct{}{},
	}

	consumer.took(map[string][]int32{stream: {0, 1, 2}})
	if held := consumer.holding(); held != 3 {
		t.Errorf("the reader holds %d partitions after being given three", held)
	}

	consumer.gave(map[string][]int32{stream: {1, 2}})
	if held := consumer.holding(); held != 1 {
		t.Errorf("the reader holds %d partitions after giving two back", held)
	}

	consumer.took(map[string][]int32{stream: {0, 5}})
	if got := consumer.Assigned(); len(got) != 2 || got[0] != 0 || got[1] != 5 {
		t.Errorf("the reader reports holding %v", got)
	}
}

// A reader that only gives partitions back is never asked for offsets to
// adjust, so the assignment it is left with has to be checked where it changed.
func TestAReaderLeftWithAnAssignmentItCannotAnswerStopsToo(t *testing.T) {
	refusal := errors.New("a rule needs the whole stream")
	consumer := &Consumer{
		topic:    stream,
		metrics:  NewConsumerMetrics(metrics.New("test")),
		assigned: map[int32]struct{}{0: {}, 1: {}, 2: {}},
		recovery: func(held int32) (time.Duration, error) {
			if held < 3 {
				return 0, refusal
			}
			return 0, nil
		},
	}

	consumer.gave(map[string][]int32{stream: {2}})
	if err := consumer.refused(); !errors.Is(err, refusal) {
		t.Fatalf("a reader left with two of three partitions kept counting across them: %v", err)
	}
}

// What is left is what is asked about. Whether holding nothing is answerable is
// a question about rules, so it is answered where the rules are.
func TestWhatIsLeftAfterARevocationIsWhatTheReaderIsAskedAbout(t *testing.T) {
	var asked []int32
	consumer := &Consumer{
		topic:    stream,
		metrics:  NewConsumerMetrics(metrics.New("test")),
		assigned: map[int32]struct{}{0: {}, 1: {}},
		recovery: func(held int32) (time.Duration, error) {
			asked = append(asked, held)
			return 0, nil
		},
	}

	consumer.gave(map[string][]int32{stream: {1}})
	consumer.gave(map[string][]int32{stream: {0}})
	if len(asked) != 2 || asked[0] != 1 || asked[1] != 0 {
		t.Fatalf("the reader was asked about %v as it gave its partitions back", asked)
	}
}
