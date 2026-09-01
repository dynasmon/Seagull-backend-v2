package detectionstate_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
)

const window = time.Minute

var epoch = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

func at(seconds int) time.Time { return epoch.Add(time.Duration(seconds) * time.Second) }

func saw(event string, second int, value string) detectionstate.Observation {
	return detectionstate.Observation{Event: event, At: at(second), Value: value}
}

func kept(t *testing.T, bounds detectionstate.Bounds) *detectionstate.Keeper {
	t.Helper()
	keeper, err := detectionstate.NewKeeper(bounds)
	if err != nil {
		t.Fatalf("open a keeper: %v", err)
	}
	return keeper
}

func observe(t *testing.T, keeper *detectionstate.Keeper, key detectionstate.Key, seen detectionstate.Observation) detectionstate.State {
	t.Helper()
	state, err := keeper.Observe(context.Background(), key, seen, window)
	if err != nil {
		t.Fatalf("observe %s: %v", seen.Event, err)
	}
	return state
}

func keyed(group string) detectionstate.Key {
	return detectionstate.KeyFor(tenant, rule, 1, []detection.Binding{bound("authentication.source.ip", group)})
}

func TestACountRisesWithWhatOneKeyHasSeenAndTwoKeysCountApart(t *testing.T) {
	keeper := kept(t, bounded())
	here, elsewhere := keyed("203.0.113.10"), keyed("198.51.100.9")

	observe(t, keeper, here, saw("e1", 0, ""))
	state := observe(t, keeper, here, saw("e2", 1, ""))
	if state.Count != 2 || state.First != at(0) || state.Last != at(1) {
		t.Errorf("two events under one key came to %+v", state)
	}
	if state.Span() != time.Second {
		t.Errorf("the span of two events a second apart was %s", state.Span())
	}

	other := observe(t, keeper, elsewhere, saw("e3", 2, ""))
	if other.Count != 1 {
		t.Errorf("a second key started at %d rather than at one", other.Count)
	}
	if keeper.Keys() != 2 {
		t.Errorf("two groups made %d keys", keeper.Keys())
	}
}

func TestTheSameEventTwiceCountsOnce(t *testing.T) {
	keeper := kept(t, bounded())
	key := keyed("203.0.113.10")

	observe(t, keeper, key, saw("e1", 0, "root"))
	state := observe(t, keeper, key, saw("e1", 0, "root"))
	if state.Count != 1 || state.Distinct != 1 {
		t.Errorf("a redelivered event was counted twice: %+v", state)
	}
}

// The engine commits its group position after a batch, so a crash redelivers
// the batch it was in the middle of. State that counted it twice would report a
// threshold nothing reached.
func TestAReplayedStreamRebuildsTheSameState(t *testing.T) {
	stream := []detectionstate.Observation{
		saw("e1", 0, "root"), saw("e2", 5, "admin"), saw("e3", 9, "root"),
		saw("e4", 20, "root"), saw("e5", 31, "backup"),
	}

	once := kept(t, bounded())
	var first detectionstate.State
	for _, seen := range stream {
		first = observe(t, once, keyed("203.0.113.10"), seen)
	}

	twice := kept(t, bounded())
	var second detectionstate.State
	for _, seen := range stream {
		observe(t, twice, keyed("203.0.113.10"), seen)
		second = observe(t, twice, keyed("203.0.113.10"), seen)
	}

	if first != second {
		t.Errorf("replaying the stream made %+v where reading it once made %+v", second, first)
	}
}

func TestWhatFallsOutOfTheWindowIsForgotten(t *testing.T) {
	keeper := kept(t, bounded())
	key := keyed("203.0.113.10")

	observe(t, keeper, key, saw("e1", 0, ""))
	observe(t, keeper, key, saw("e2", 30, ""))
	state := observe(t, keeper, key, saw("e3", 90, ""))

	if state.Count != 2 || state.First != at(30) {
		t.Errorf("a minute after the first event the key still held %+v", state)
	}
}

func TestAnObservationOlderThanTheWindowIsRefusedAndMovesNothing(t *testing.T) {
	keeper := kept(t, bounded())
	key := keyed("203.0.113.10")

	observe(t, keeper, key, saw("e1", 0, ""))
	before := observe(t, keeper, key, saw("e2", 100, ""))

	state, err := keeper.Observe(context.Background(), key, saw("e3", 30, ""), window)
	if !errors.Is(err, detectionstate.ErrTooLate) {
		t.Fatalf("an observation seventy seconds behind the window gave %v", err)
	}
	if state != before {
		t.Errorf("a refused observation changed the key from %+v to %+v", before, state)
	}
}

func TestAnObservationOutOfOrderLandsInEventTime(t *testing.T) {
	keeper := kept(t, bounded())
	key := keyed("203.0.113.10")

	observe(t, keeper, key, saw("e1", 0, ""))
	observe(t, keeper, key, saw("e3", 30, ""))
	observe(t, keeper, key, saw("e2", 15, ""))

	state := observe(t, keeper, key, saw("e4", 70, ""))
	if state.Count != 3 || state.First != at(15) {
		t.Errorf("the window kept the wrong three of four events: %+v", state)
	}
}

func TestCardinalityCountsDistinctValuesAndForgetsThemWithTheWindow(t *testing.T) {
	keeper := kept(t, bounded())
	key := keyed("203.0.113.10")

	observe(t, keeper, key, saw("e1", 0, "root"))
	observe(t, keeper, key, saw("e2", 1, "admin"))
	state := observe(t, keeper, key, saw("e3", 2, "root"))
	if state.Count != 3 || state.Distinct != 2 {
		t.Errorf("three events naming two users came to %+v", state)
	}

	state = observe(t, keeper, key, saw("e4", 70, "backup"))
	if state.Count != 1 || state.Distinct != 1 {
		t.Errorf("a minute later the key still held %+v", state)
	}

	state = observe(t, keeper, key, saw("e5", 71, ""))
	if state.Count != 2 || state.Distinct != 1 {
		t.Errorf("an event naming nothing changed the cardinality: %+v", state)
	}
}

func TestAFullKeyDiscardsItsOldestAndSaysSo(t *testing.T) {
	keeper := kept(t, detectionstate.Bounds{Window: window, ObservationsPerKey: 4, Keys: 4})
	key := keyed("203.0.113.10")

	var state detectionstate.State
	for second := range 6 {
		state = observe(t, keeper, key, saw(fmt.Sprintf("e%d", second), second, ""))
	}

	if state.Count != 4 || !state.Saturated {
		t.Errorf("six events under a key that holds four came to %+v", state)
	}
	if state.First != at(2) {
		t.Errorf("the key discarded the wrong two of six, keeping from %s", state.First)
	}
}

func TestANewKeyBeyondTheCeilingIsRefusedAndTheOldOnesSurvive(t *testing.T) {
	keeper := kept(t, detectionstate.Bounds{Window: window, ObservationsPerKey: 8, Keys: 2})

	observe(t, keeper, keyed("203.0.113.10"), saw("e1", 0, ""))
	observe(t, keeper, keyed("203.0.113.11"), saw("e2", 0, ""))

	if _, err := keeper.Observe(context.Background(), keyed("203.0.113.12"), saw("e3", 0, ""), window); !errors.Is(err, detectionstate.ErrAtCapacity) {
		t.Fatalf("a third key in a store bounded to two gave %v", err)
	}

	state := observe(t, keeper, keyed("203.0.113.10"), saw("e4", 1, ""))
	if state.Count != 2 {
		t.Errorf("a refused key cost an existing one its count: %+v", state)
	}
	if keeper.Keys() != 2 {
		t.Errorf("the store holds %d keys, not the two it was bounded to", keeper.Keys())
	}
}

func TestAKeyNobodyObservesAgainMakesRoomForANewOne(t *testing.T) {
	keeper := kept(t, detectionstate.Bounds{Window: window, ObservationsPerKey: 8, Keys: 2})

	observe(t, keeper, keyed("203.0.113.10"), saw("e1", 0, ""))
	observe(t, keeper, keyed("203.0.113.11"), saw("e2", 0, ""))
	observe(t, keeper, keyed("203.0.113.10"), saw("e3", 600, ""))

	state := observe(t, keeper, keyed("203.0.113.12"), saw("e4", 601, ""))
	if state.Count != 1 {
		t.Errorf("a new key admitted in place of an idle one started at %+v", state)
	}
	if keeper.Keys() != 2 {
		t.Errorf("reclaiming left %d keys rather than two", keeper.Keys())
	}
}

func TestTheWatermarkOnlyMovesForward(t *testing.T) {
	keeper := kept(t, bounded())
	key := keyed("203.0.113.10")

	observe(t, keeper, key, saw("e1", 100, ""))
	observe(t, keeper, key, saw("e2", 50, ""))

	if reached := keeper.Watermark(); reached != at(100) {
		t.Errorf("an event arriving out of order pulled the watermark back to %s", reached)
	}
}

func TestAKeeperRefusesWhatItCannotHold(t *testing.T) {
	if _, err := detectionstate.NewKeeper(detectionstate.Bounds{}); !errors.Is(err, detectionstate.ErrNoWindow) {
		t.Fatalf("a keeper with no bounds opened with %v", err)
	}

	keeper := kept(t, bounded())
	key := keyed("203.0.113.10")

	if _, err := keeper.Observe(context.Background(), key, saw("e1", 0, ""), 0); !errors.Is(err, detectionstate.ErrNoWindow) {
		t.Errorf("a window of nothing gave %v", err)
	}
	if _, err := keeper.Observe(context.Background(), key, saw("e1", 0, ""), 2*window); !errors.Is(err, detectionstate.ErrWindowTooLong) {
		t.Errorf("a rule remembering longer than the store was bounded to gave %v", err)
	}
	if _, err := keeper.Observe(context.Background(), key, detectionstate.Observation{At: at(0)}, window); !errors.Is(err, detectionstate.ErrNoEvent) {
		t.Errorf("an observation naming no event gave %v", err)
	}
	if keeper.Keys() != 0 {
		t.Errorf("a refused observation opened %d keys", keeper.Keys())
	}
}

func TestObservingStopsWhenTheCallerIsGone(t *testing.T) {
	keeper := kept(t, bounded())
	ctx, stop := context.WithCancel(context.Background())
	stop()

	if _, err := keeper.Observe(ctx, keyed("203.0.113.10"), saw("e1", 0, ""), window); !errors.Is(err, context.Canceled) {
		t.Errorf("observing after the caller went away gave %v", err)
	}
}

func TestConcurrentObserversAgreeOnWhatAKeyHasSeen(t *testing.T) {
	keeper := kept(t, detectionstate.Bounds{Window: time.Hour, ObservationsPerKey: 128, Keys: 8})
	key := keyed("203.0.113.10")

	var writers sync.WaitGroup
	for writer := range 8 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for index := range 8 {
				seen := detectionstate.Observation{Event: fmt.Sprintf("e%d-%d", writer, index), At: at(index)}
				if _, err := keeper.Observe(context.Background(), key, seen, time.Hour); err != nil {
					t.Errorf("observe from writer %d: %v", writer, err)
				}
			}
		}()
	}
	writers.Wait()

	state := observe(t, keeper, key, detectionstate.Observation{Event: "e0-0", At: at(0)})
	if state.Count != 64 {
		t.Errorf("eight writers of eight events each came to %d", state.Count)
	}
	if reached := keeper.Watermark(); reached != at(7) {
		t.Errorf("the watermark reached %s rather than the newest event", reached)
	}
}
