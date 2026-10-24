package broker

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
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
		topic:   stream,
		metrics: NewConsumerMetrics(metrics.New("test")),
		endOffsets: staticEndOffsets{
			starts:  listed(map[int32]int64{0: 0, 1: 0}),
			offsets: ends,
			after:   after,
		},
		recovery: recovery,
		lastRecordTimes: func(_ context.Context, positions map[int32]int64) (map[int32]time.Time, error) {
			times := make(map[int32]time.Time, len(positions))
			for partition := range positions {
				times[partition] = time.Now()
			}
			return times, nil
		},
		logger:   slog.New(slog.DiscardHandler),
		assigned: map[int32]struct{}{0: {}, 1: {}},
	}
}

type timeline struct {
	times  map[int32][]time.Time
	starts map[int32]int64
}

func spaced(from time.Time, count int, apart time.Duration) []time.Time {
	times := make([]time.Time, count)
	for offset := range times {
		times[offset] = from.Add(time.Duration(offset) * apart)
	}
	return times
}

func (l timeline) ListStartOffsets(context.Context, ...string) (kadm.ListedOffsets, error) {
	starts := make(map[int32]int64, len(l.times))
	for partition := range l.times {
		starts[partition] = l.starts[partition]
	}
	return listed(starts), nil
}

func (l timeline) ListEndOffsets(context.Context, ...string) (kadm.ListedOffsets, error) {
	ends := make(map[int32]int64, len(l.times))
	for partition, times := range l.times {
		ends[partition] = int64(len(times))
	}
	return listed(ends), nil
}

func (l timeline) ListOffsetsAfter(_ context.Context, _ string, milliseconds map[int32]int64) (kadm.ListedOffsets, error) {
	after := make(map[int32]int64, len(milliseconds))
	for partition, millisecond := range milliseconds {
		times := l.times[partition]
		after[partition] = -1
		for offset := l.starts[partition]; offset < int64(len(times)); offset++ {
			if times[offset].UnixMilli() >= millisecond {
				after[partition] = offset
				break
			}
		}
	}
	return listed(after), nil
}

func (l timeline) lastRecordTimes(_ context.Context, positions map[int32]int64) (map[int32]time.Time, error) {
	times := make(map[int32]time.Time, len(positions))
	for partition, position := range positions {
		if position-1 >= l.starts[partition] {
			times[partition] = l.times[partition][position-1]
		}
	}
	return times, nil
}

func behind(t *testing.T, topic timeline, recovery time.Duration) (*Consumer, *metrics.Registry, *bytes.Buffer) {
	t.Helper()

	registry := metrics.New("test")
	written := &bytes.Buffer{}
	assigned := make(map[int32]struct{}, len(topic.times))
	for partition := range topic.times {
		assigned[partition] = struct{}{}
	}
	return &Consumer{
		topic:           stream,
		metrics:         NewConsumerMetrics(registry),
		endOffsets:      topic,
		recovery:        func(int32) (time.Duration, error) { return recovery, nil },
		lastRecordTimes: topic.lastRecordTimes,
		logger:          slog.New(slog.NewJSONHandler(written, nil)),
		assigned:        assigned,
	}, registry, written
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

func TestAReaderBehindItsWindowIsReadBackFromTheLastRecordItCommitted(t *testing.T) {
	began := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	consumer, _, written := behind(t, timeline{times: map[int32][]time.Time{
		0: spaced(began, 200, 10*time.Second),
	}}, 10*time.Minute)

	rebuilt, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 120}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 59 {
		t.Errorf("a reader three hours behind resumes at %d, want 59, the first record inside the ten minutes before the last one it committed", got)
	}
	if strings.Contains(written.String(), "state_rebuild_incomplete") {
		t.Errorf("a window the topic still holds was reported incomplete: %s", written)
	}
}

func TestEachPartitionIsReadBackFromTheLastRecordItCommitted(t *testing.T) {
	began := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	consumer, _, _ := behind(t, timeline{times: map[int32][]time.Time{
		0: spaced(began, 200, 10*time.Second),
		1: spaced(began, 60, 30*time.Second),
	}}, 10*time.Minute)

	rebuilt, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 120, 1: 40}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 59 {
		t.Errorf("partition 0 resumes at %d, want 59", got)
	}
	if got := at(t, rebuilt, 1); got != 19 {
		t.Errorf("partition 1 resumes at %d, want 19", got)
	}
}

func TestAReadBackToTheFirstRecordEverWrittenReportsNothingMissing(t *testing.T) {
	began := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	consumer, _, written := behind(t, timeline{times: map[int32][]time.Time{
		0: spaced(began, 200, 10*time.Second),
	}}, 10*time.Minute)

	rebuilt, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 30}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 0 {
		t.Errorf("a window holding every record written resumes at %d, want 0", got)
	}
	if strings.Contains(written.String(), "state_rebuild_incomplete") {
		t.Errorf("a window the topic holds whole was reported incomplete: %s", written)
	}
}

func TestAPartitionCommittedAtItsFirstRecordHasNothingToReadBack(t *testing.T) {
	consumer, _, written := behind(t, timeline{times: map[int32][]time.Time{
		0: spaced(time.Now().Add(-time.Hour), 10, time.Second),
	}}, 10*time.Minute)

	rebuilt, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 0}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 0 {
		t.Errorf("a partition that committed nothing yet resumes at %d", got)
	}
	if strings.Contains(written.String(), "state_rebuild_incomplete") {
		t.Errorf("a partition with nothing before it was reported incomplete: %s", written)
	}
}

func TestAPartitionWhoseLastCommittedRecordIsGoneIsLeftWhereItStoppedAndReported(t *testing.T) {
	began := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	consumer, registry, written := behind(t, timeline{
		times:  map[int32][]time.Time{0: spaced(began, 200, 10*time.Second)},
		starts: map[int32]int64{0: 120},
	}, 10*time.Minute)

	rebuilt, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 120}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 120 {
		t.Errorf("a partition whose window retention removed resumes at %d", got)
	}
	metric := `seagull_backbone_state_rebuild_incomplete_total{partition="0",topic="security.events.raw"}`
	if got := metricValue(t, registry, metric); got != 1 {
		t.Errorf("%s is %.0f, want 1", metric, got)
	}
	if !strings.Contains(written.String(), `"reason":"last_committed_record_gone"`) {
		t.Errorf("a window retention removed was not logged as such: %s", written)
	}
}

func TestAPartitionWhoseUndecidedRecordsAreGoneIsReportedAsSuch(t *testing.T) {
	began := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	consumer, registry, written := behind(t, timeline{
		times:  map[int32][]time.Time{0: spaced(began, 200, 10*time.Second)},
		starts: map[int32]int64{0: 150},
	}, 10*time.Minute)

	rebuilt, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 120}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 120 {
		t.Errorf("a partition whose undecided records retention removed was moved to %d", got)
	}
	metric := `seagull_backbone_state_rebuild_incomplete_total{partition="0",topic="security.events.raw"}`
	if got := metricValue(t, registry, metric); got != 1 {
		t.Errorf("%s is %.0f, want 1", metric, got)
	}
	if !strings.Contains(written.String(), `"reason":"undecided_records_gone"`) {
		t.Errorf("records removed before anything decided them were not logged as such: %s", written)
	}
}

func TestASparsePartitionWhoseOlderRecordsRetentionRemovedIsReadBackWithoutAlarm(t *testing.T) {
	began := time.Now().Add(-8 * 24 * time.Hour).Truncate(time.Second)
	burst := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	consumer, _, written := behind(t, timeline{
		times:  map[int32][]time.Time{0: append(spaced(began, 150, time.Minute), spaced(burst, 50, time.Second)...)},
		starts: map[int32]int64{0: 150},
	}, 10*time.Minute)

	rebuilt, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 200}))
	if err != nil {
		t.Fatalf("rebuild the assignment: %v", err)
	}
	if got := at(t, rebuilt, 0); got != 150 {
		t.Errorf("a partition whose last burst sits inside one window resumes at %d, want 150", got)
	}
	if strings.Contains(written.String(), "state_rebuild_incomplete") {
		t.Errorf("records older than the window, removed by retention, were reported as a lost window: %s", written)
	}
}

func TestABackboneThatCannotSayWhereAPartitionStoppedStopsTheReader(t *testing.T) {
	unavailable := errors.New("broker unavailable")
	consumer, _, _ := behind(t, timeline{times: map[int32][]time.Time{
		0: spaced(time.Now().Add(-time.Hour), 200, time.Second),
	}}, 10*time.Minute)
	consumer.lastRecordTimes = func(context.Context, map[int32]int64) (map[int32]time.Time, error) {
		return nil, unavailable
	}

	if _, err := consumer.rebuild(context.Background(), committed(map[int32]int64{0: 120})); !errors.Is(err, unavailable) {
		t.Fatalf("an unreadable last record was treated as nothing to rebuild: %v", err)
	}
	if err := consumer.refused(); !errors.Is(err, unavailable) {
		t.Fatalf("the refusal did not reach the caller waiting on Consume: %v", err)
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
