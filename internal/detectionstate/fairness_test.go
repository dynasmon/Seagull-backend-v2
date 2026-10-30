package detectionstate_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
)

func from(partition int32, seen detectionstate.Observation) detectionstate.Observation {
	seen.Partition = partition
	return seen
}

func seenAt(name string, milliseconds int) detectionstate.Observation {
	return detectionstate.Observation{Event: named(name), At: epoch.Add(time.Duration(milliseconds) * time.Millisecond)}
}

func refusedWith(t *testing.T, keeper *detectionstate.Keeper, key detectionstate.Key, seen detectionstate.Observation, expected error) {
	t.Helper()

	if _, err := keeper.Observe(context.Background(), key, seen, window); !errors.Is(err, expected) {
		t.Fatalf("observing %v answered %v, want %v", seen.Event, err, expected)
	}
}

func TestATenantFloodingGroupValuesLeavesRoomForAnotherTenant(t *testing.T) {
	keeper := kept(t, quotas(8, 4, 4))

	for index := range 64 {
		group := fmt.Sprintf("flood-%d", index)
		key, seen := ownedBy("flooding", rule, group), saw(group, 0, "")
		if index < 4 {
			observe(t, keeper, key, seen)
			continue
		}
		refusedWith(t, keeper, key, seen, detectionstate.ErrTenantAtCapacity)
	}

	if state := observe(t, keeper, ownedBy("another", rule, "203.0.113.10"), saw("e1", 0, "")); state.Count != 1 {
		t.Errorf("another tenant's new key started at %+v", state)
	}
	if keeper.Keys() != 5 {
		t.Errorf("four keys of a flood and one of another tenant came to %d", keeper.Keys())
	}
}

func TestARuleFloodingGroupValuesLeavesRoomForTheOtherRulesOfItsTenant(t *testing.T) {
	keeper := kept(t, quotas(8, 4, 2))
	const noisy, quiet = detection.ID("noisy"), detection.ID("quiet")

	observe(t, keeper, ownedBy(tenant, noisy, "a"), saw("e1", 0, ""))
	observe(t, keeper, ownedBy(tenant, noisy, "b"), saw("e2", 0, ""))
	refusedWith(t, keeper, ownedBy(tenant, noisy, "c"), saw("e3", 0, ""), detectionstate.ErrRuleAtCapacity)

	observe(t, keeper, ownedBy(tenant, quiet, "a"), saw("e4", 0, ""))
	if state := observe(t, keeper, ownedBy(tenant, noisy, "a"), saw("e5", 1, "")); state.Count != 2 {
		t.Errorf("a key its rule already held stopped counting at its quota: %+v", state)
	}
}

func TestTheStoreCeilingHoldsHoweverManyTenantsAsk(t *testing.T) {
	keeper := kept(t, quotas(4, 2, 2))

	for _, owner := range []string{"one", "two"} {
		observe(t, keeper, ownedBy(owner, rule, "a"), saw("e1", 0, ""))
		observe(t, keeper, ownedBy(owner, rule, "b"), saw("e2", 0, ""))
	}

	refusedWith(t, keeper, ownedBy("three", rule, "a"), saw("e3", 0, ""), detectionstate.ErrAtCapacity)
	if keeper.Keys() != 4 {
		t.Errorf("a store bounded to four holds %d", keeper.Keys())
	}
}

func TestAKeyPastItsWindowGivesBackTheRoomOfItsTenant(t *testing.T) {
	keeper := kept(t, quotas(8, 2, 1))

	observe(t, keeper, ownedBy(tenant, "first", "a"), saw("e1", 0, ""))
	observe(t, keeper, ownedBy(tenant, "second", "a"), saw("e2", 600, ""))
	observe(t, keeper, ownedBy(tenant, "third", "a"), saw("e3", 601, ""))

	if keeper.Keys() != 2 {
		t.Errorf("a tenant allowed two keys holds %d", keeper.Keys())
	}
}

func TestAKeyPastItsWindowGivesBackTheRoomOfItsRule(t *testing.T) {
	keeper := kept(t, quotas(8, 8, 1))

	observe(t, keeper, keyed("203.0.113.10"), saw("e1", 0, ""))
	observe(t, keeper, keyed("203.0.113.11"), saw("e2", 600, ""))

	if keeper.Keys() != 1 {
		t.Errorf("a rule allowed one key holds %d", keeper.Keys())
	}
}

func TestAKeyObservedAgainIsNotPast(t *testing.T) {
	keeper := kept(t, quotas(8, 2, 2))
	again := keyed("203.0.113.10")

	observe(t, keeper, again, saw("e1", 0, ""))
	observe(t, keeper, keyed("203.0.113.11"), saw("e2", 1, ""))
	observe(t, keeper, again, saw("e3", 600, ""))

	observe(t, keeper, keyed("203.0.113.12"), saw("e4", 601, ""))

	if state := observe(t, keeper, again, saw("e5", 602, "")); state.Count != 2 {
		t.Errorf("a key observed a second ago was reclaimed for being idle: %+v", state)
	}
}

func TestAPartitionBehindTheStreamKeepsItsKeys(t *testing.T) {
	keeper := kept(t, quotas(8, 2, 2))
	behind := keyed("203.0.113.10")

	observe(t, keeper, behind, from(1, saw("e1", 0, "")))
	observe(t, keeper, keyed("203.0.113.11"), from(0, saw("e2", 600, "")))

	refusedWith(t, keeper, keyed("203.0.113.12"), from(1, saw("e3", 1, "")), detectionstate.ErrTenantAtCapacity)

	if state := observe(t, keeper, behind, from(1, saw("e4", 2, ""))); state.Count != 2 {
		t.Errorf("a key of a partition behind the stream was reclaimed: %+v", state)
	}
}

// A partition this process lost delivers nothing more, so a watermark of its own
// would stand still and its keys would hold their tenant's room for as long as
// the process lives (ADR 23 leaves them to be reclaimed like any other).
func TestAPartitionThatStoppedDeliveringLetsItsKeysGo(t *testing.T) {
	keeper := kept(t, quotas(8, 2, 2))

	observe(t, keeper, keyed("203.0.113.10"), from(1, saw("e1", 0, "")))
	observe(t, keeper, keyed("203.0.113.11"), from(0, saw("e2", 0, "")))
	observe(t, keeper, keyed("203.0.113.11"), from(0, saw("e3", 600, "")))

	observe(t, keeper, keyed("203.0.113.12"), from(0, saw("e4", 601, "")))

	if keeper.Keys() != 2 {
		t.Errorf("a tenant allowed two keys holds %d", keeper.Keys())
	}
}

func TestAPartitionThatStoppedBehindTheStreamIsTimedFromWhereItStopped(t *testing.T) {
	keeper := kept(t, quotas(8, 2, 2))
	stopped := keyed("203.0.113.10")

	observe(t, keeper, keyed("203.0.113.11"), from(0, saw("e1", 60, "")))
	observe(t, keeper, stopped, from(1, saw("e2", 0, "")))

	refusedWith(t, keeper, keyed("203.0.113.12"), from(0, saw("e3", 119, "")), detectionstate.ErrTenantAtCapacity)
	observe(t, keeper, keyed("203.0.113.13"), from(0, saw("e4", 121, "")))

	if state := observe(t, keeper, keyed("203.0.113.13"), from(0, saw("e5", 122, ""))); state.Count != 2 {
		t.Errorf("the key that replaced one past its window came to %+v", state)
	}
}

// A tenant may hold a clock ahead of everyone's and a flood at its quota, and
// neither may cost another tenant a count: what is past is only ever asked of
// the tenant under pressure.
func TestATenantUnderPressureReclaimsNothingOfAnothers(t *testing.T) {
	keeper := kept(t, quotas(8, 2, 2))
	victim := ownedBy("victim", rule, "203.0.113.10")

	observe(t, keeper, victim, saw("e1", 0, ""))

	observe(t, keeper, ownedBy("flooding", rule, "a"), saw("f1", 600, ""))
	observe(t, keeper, ownedBy("flooding", rule, "b"), saw("f2", 600, ""))
	refusedWith(t, keeper, ownedBy("flooding", rule, "c"), saw("f3", 600, ""), detectionstate.ErrTenantAtCapacity)

	if state := observe(t, keeper, victim, saw("e2", 1, "")); state.Count != 2 {
		t.Errorf("another tenant's flood cost this one its count: %+v", state)
	}
}

func TestAWatermarkBelongsToOneTenantOnOnePartition(t *testing.T) {
	keeper := kept(t, quotas(8, 4, 4))

	observe(t, keeper, ownedBy("one", rule, "a"), from(0, saw("e1", 100, "")))
	observe(t, keeper, ownedBy("two", rule, "a"), from(0, saw("e2", 50, "")))
	observe(t, keeper, ownedBy("one", rule, "b"), from(1, saw("e3", 10, "")))

	for _, expected := range []struct {
		owner     string
		partition int32
		reached   time.Time
	}{
		{"one", 0, at(100)},
		{"two", 0, at(50)},
		{"one", 1, at(10)},
	} {
		if reached := keeper.Watermark(expected.owner, expected.partition); reached != expected.reached {
			t.Errorf("%s on partition %d reached %s, want %s", expected.owner, expected.partition, reached, expected.reached)
		}
	}
}

func TestAStoreAtItsCeilingTakesBackTheKeysOfATenantGoneQuiet(t *testing.T) {
	keeper := kept(t, quotas(2, 2, 2))

	observe(t, keeper, ownedBy("quiet", rule, "a"), saw("e1", 0, ""))
	observe(t, keeper, ownedBy("quiet", rule, "b"), saw("e2", 0, ""))

	observe(t, keeper, ownedBy("busy", rule, "a"), saw("e3", 600, ""))

	if keeper.Keys() != 1 {
		t.Errorf("a store that reclaimed a quiet tenant holds %d keys", keeper.Keys())
	}
}

// Walking every tenant on every partition is the one thing here whose cost does
// not follow from a key, and a store at its ceiling is asked on every event a
// flood sends. What is refused in between is refused for a second of the stream.
func TestAStoreAtItsCeilingAsksEveryTenantOnceASecondOfTheStream(t *testing.T) {
	keeper := kept(t, quotas(2, 2, 2))

	observe(t, keeper, ownedBy("quiet", rule, "a"), seenAt("e1", 0))
	observe(t, keeper, ownedBy("busy", rule, "a"), seenAt("e2", 60_000))

	refusedWith(t, keeper, ownedBy("third", rule, "a"), seenAt("e3", 60_000), detectionstate.ErrAtCapacity)
	refusedWith(t, keeper, ownedBy("third", rule, "a"), seenAt("e4", 60_500), detectionstate.ErrAtCapacity)

	observe(t, keeper, ownedBy("third", rule, "a"), seenAt("e5", 61_000))
	if keeper.Keys() != 2 {
		t.Errorf("a store bounded to two holds %d keys", keeper.Keys())
	}
}

func TestAStoreAtItsCeilingLetsATenantReclaimItsOwnKeysAtOnce(t *testing.T) {
	keeper := kept(t, quotas(2, 2, 2))

	observe(t, keeper, ownedBy("one", rule, "a"), seenAt("e1", 0))
	observe(t, keeper, ownedBy("two", rule, "a"), seenAt("e2", 60_000))
	refusedWith(t, keeper, ownedBy("three", rule, "a"), seenAt("e3", 60_000), detectionstate.ErrAtCapacity)

	observe(t, keeper, ownedBy("one", rule, "b"), seenAt("e4", 60_500))
	if keeper.Keys() != 2 {
		t.Errorf("a store bounded to two holds %d keys", keeper.Keys())
	}
}

func TestTheFullestTenantAndRuleAreCounted(t *testing.T) {
	keeper := kept(t, quotas(8, 4, 4))

	observe(t, keeper, ownedBy("one", "first", "a"), saw("e1", 0, ""))
	observe(t, keeper, ownedBy("one", "first", "b"), saw("e2", 0, ""))
	observe(t, keeper, ownedBy("one", "second", "a"), saw("e3", 0, ""))
	observe(t, keeper, ownedBy("two", "first", "a"), saw("e4", 0, ""))

	if fullest := keeper.FullestTenant(); fullest != 3 {
		t.Errorf("the fullest tenant holds %d keys, want 3", fullest)
	}
	if fullest := keeper.FullestRule(); fullest != 2 {
		t.Errorf("the fullest rule holds %d keys, want 2", fullest)
	}
}

// The definition, written the slow way: a walk over every key decides what is
// past. Whatever the index does has to come to the same answer at every step,
// out of order, behind the stream and under every quota.
type oracleKey struct {
	last      time.Time
	window    time.Duration
	partition int32
}

type oracleClock struct{ watermark, heard time.Time }

type oracle struct {
	bounds detectionstate.Bounds
	keys   map[detectionstate.Key]*oracleKey
	clocks map[string]map[int32]*oracleClock
	newest time.Time
	swept  time.Time
}

func (o *oracle) ofTenant(owner string) int {
	held := 0
	for key := range o.keys {
		if key.Tenant == owner {
			held++
		}
	}
	return held
}

func (o *oracle) ofRule(owner string, asking detection.ID) int {
	held := 0
	for key := range o.keys {
		if key.Tenant == owner && key.Rule == asking {
			held++
		}
	}
	return held
}

func (o *oracle) reclaim(owner string) {
	for key, entry := range o.keys {
		if key.Tenant != owner {
			continue
		}
		clock := o.clocks[owner][entry.partition]
		if entry.last.Add(entry.window).Before(clock.watermark.Add(o.newest.Sub(clock.heard))) {
			delete(o.keys, key)
		}
	}
	for partition := range o.clocks[owner] {
		filed := false
		for key, entry := range o.keys {
			filed = filed || key.Tenant == owner && entry.partition == partition
		}
		if !filed {
			delete(o.clocks[owner], partition)
		}
	}
}

func (o *oracle) fold(key detectionstate.Key, seen detectionstate.Observation, within time.Duration) error {
	if seen.At.After(o.newest) {
		o.newest = seen.At
	}
	if clock := o.clocks[key.Tenant][seen.Partition]; clock != nil {
		if seen.At.After(clock.watermark) {
			clock.watermark = seen.At
		}
		clock.heard = o.newest
	}

	entry, opened := o.keys[key]
	if opened {
		if seen.At.Before(entry.last.Add(-within)) {
			return detectionstate.ErrTooLate
		}
		if seen.At.After(entry.last) {
			entry.last = seen.At
		}
		return nil
	}

	if o.ofRule(key.Tenant, key.Rule) >= o.bounds.KeysPerRule || o.ofTenant(key.Tenant) >= o.bounds.KeysPerTenant || len(o.keys) >= o.bounds.Keys {
		o.reclaim(key.Tenant)
		if o.ofTenant(key.Tenant) >= o.bounds.KeysPerTenant {
			return detectionstate.ErrTenantAtCapacity
		}
		if o.ofRule(key.Tenant, key.Rule) >= o.bounds.KeysPerRule {
			return detectionstate.ErrRuleAtCapacity
		}
	}
	if len(o.keys) >= o.bounds.Keys {
		if o.newest.Sub(o.swept) >= time.Second {
			o.swept = o.newest
			for owner := range o.clocks {
				o.reclaim(owner)
			}
		}
		if len(o.keys) >= o.bounds.Keys {
			return detectionstate.ErrAtCapacity
		}
	}

	o.keys[key] = &oracleKey{last: seen.At, window: within, partition: seen.Partition}
	if o.clocks[key.Tenant] == nil {
		o.clocks[key.Tenant] = make(map[int32]*oracleClock)
	}
	if o.clocks[key.Tenant][seen.Partition] == nil {
		o.clocks[key.Tenant][seen.Partition] = &oracleClock{watermark: seen.At, heard: o.newest}
	}
	return nil
}

func (o *oracle) fullestTenant() int {
	fullest := 0
	for owner := range o.clocks {
		fullest = max(fullest, o.ofTenant(owner))
	}
	return fullest
}

func (o *oracle) fullestRule() int {
	fullest := 0
	for key := range o.keys {
		fullest = max(fullest, o.ofRule(key.Tenant, key.Rule))
	}
	return fullest
}

func TestTheIndexReclaimsExactlyWhatAWalkOverEveryKeyWould(t *testing.T) {
	bounds := detectionstate.Bounds{Window: time.Hour, ObservationsPerKey: 4, Keys: 24, KeysPerTenant: 12, KeysPerRule: 6}
	rules := []struct {
		id     detection.ID
		within time.Duration
	}{{"short", 30 * time.Second}, {"long", 90 * time.Second}, {"longest", 5 * time.Minute}}

	for seed := range uint64(64) {
		random := rand.New(rand.NewPCG(seed, 1))
		keeper := kept(t, bounds)
		model := &oracle{
			bounds: bounds,
			keys:   make(map[detectionstate.Key]*oracleKey),
			clocks: make(map[string]map[int32]*oracleClock),
		}

		now := at(0)
		for step := range 2_000 {
			now = now.Add(time.Duration(random.IntN(5)) * time.Second)

			asked := rules[random.IntN(len(rules))]
			owner := fmt.Sprintf("tenant-%d", random.IntN(3))
			partition := int32(random.IntN(4))
			key := ownedBy(owner, asked.id, fmt.Sprintf("group-%d", random.IntN(64)))

			happened := now.Add(-time.Duration(random.IntN(20)) * time.Second)
			if partition == 3 {
				happened = happened.Add(-10 * time.Minute)
			}
			seen := detectionstate.Observation{
				Event:     detectionstate.EventName{Agent: "web-01", ID: fmt.Sprintf("%d-%d", seed, step)},
				At:        happened,
				Partition: partition,
			}

			_, answered := keeper.Observe(context.Background(), key, seen, asked.within)
			expected := model.fold(key, seen, asked.within)
			if !errors.Is(answered, expected) {
				t.Fatalf("seed %d step %d: the keeper answered %v and the walk %v", seed, step, answered, expected)
			}
			if keeper.Keys() != len(model.keys) {
				t.Fatalf("seed %d step %d: the keeper holds %d keys and the walk %d", seed, step, keeper.Keys(), len(model.keys))
			}
			if keeper.FullestTenant() != model.fullestTenant() || keeper.FullestRule() != model.fullestRule() {
				t.Fatalf("seed %d step %d: the fullest tenant and rule are %d and %d, and the walk says %d and %d",
					seed, step, keeper.FullestTenant(), keeper.FullestRule(), model.fullestTenant(), model.fullestRule())
			}
		}
	}
}
