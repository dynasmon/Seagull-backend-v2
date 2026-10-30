package detectionstate_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
)

const millionKeys = 1 << 20

func benchKey(owner string, group int) detectionstate.Key {
	return detectionstate.Key{Tenant: owner, Rule: rule, Group: fmt.Sprintf("%032x", group)}
}

func benchSeen(name string, happened time.Time, partition int32) detectionstate.Observation {
	return detectionstate.Observation{
		Event:     detectionstate.EventName{Agent: "web-01", ID: name},
		At:        happened,
		Partition: partition,
	}
}

func filled(b *testing.B, keys int, within, apart time.Duration) (*detectionstate.Keeper, []detectionstate.Key) {
	b.Helper()

	keeper, err := detectionstate.NewKeeper(detectionstate.Bounds{
		Window:             within,
		ObservationsPerKey: 8,
		Keys:               keys,
		KeysPerTenant:      keys,
		KeysPerRule:        keys,
	})
	if err != nil {
		b.Fatalf("bound the keeper: %v", err)
	}
	held := make([]detectionstate.Key, keys)
	for index := range keys {
		held[index] = benchKey(tenant, index)
		seen := benchSeen(strconv.Itoa(index), epoch.Add(time.Duration(index)*apart), 0)
		if _, err := keeper.Observe(context.Background(), held[index], seen, within); err != nil {
			b.Fatalf("fill the keeper: %v", err)
		}
	}
	return keeper, held
}

// Every key in turn, which is the worst an index kept in order could be asked:
// each fold moves the key nearest its window's end to the far end of the queue.
func BenchmarkFoldEveryKeyInTurn(b *testing.B) {
	for _, keys := range []int{4096, millionKeys} {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			keeper, held := filled(b, keys, time.Hour, time.Microsecond)
			after := epoch.Add(time.Duration(keys) * time.Microsecond)

			b.ReportAllocs()
			b.ResetTimer()
			for index := range b.N {
				seen := benchSeen("f"+strconv.Itoa(index), after.Add(time.Duration(index)*time.Microsecond), 0)
				if _, err := keeper.Observe(context.Background(), held[index%keys], seen, time.Hour); err != nil {
					b.Fatalf("fold: %v", err)
				}
			}
		})
	}
}

func BenchmarkFoldTheBusiestKeys(b *testing.B) {
	for _, keys := range []int{4096, millionKeys} {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			keeper, held := filled(b, keys, time.Hour, time.Microsecond)
			after := epoch.Add(time.Duration(keys) * time.Microsecond)
			busiest := max(keys/100, 1)

			b.ReportAllocs()
			b.ResetTimer()
			for index := range b.N {
				seen := benchSeen("f"+strconv.Itoa(index), after.Add(time.Duration(index)*time.Microsecond), 0)
				if _, err := keeper.Observe(context.Background(), held[index%busiest], seen, time.Hour); err != nil {
					b.Fatalf("fold: %v", err)
				}
			}
		})
	}
}

// What a flood costs once there is no room: every event asks for a key, and
// every key the store holds is live.
func BenchmarkRefuseANewKeyWhileEveryKeyIsLive(b *testing.B) {
	for _, keys := range []int{4096, millionKeys} {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			keeper, _ := filled(b, keys, time.Hour, time.Microsecond)
			after := epoch.Add(time.Duration(keys) * time.Microsecond)

			b.ReportAllocs()
			b.ResetTimer()
			for index := range b.N {
				name := "n" + strconv.Itoa(index)
				seen := benchSeen(name, after, 0)
				key := detectionstate.Key{Tenant: tenant, Rule: rule, Group: name}
				if _, err := keeper.Observe(context.Background(), key, seen, time.Hour); err == nil {
					b.Fatal("a store with every key live took a new one")
				}
			}
		})
	}
}

// The steady state at a ceiling: each new key finds exactly one that has just
// gone past its window.
func BenchmarkReclaimOneKeyPastItsWindow(b *testing.B) {
	for _, keys := range []int{4096, millionKeys} {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			const apart = time.Millisecond
			within := time.Duration(keys-1) * apart
			keeper, _ := filled(b, keys, within, apart)
			after := epoch.Add(time.Duration(keys) * apart)

			b.ReportAllocs()
			b.ResetTimer()
			for index := range b.N {
				name := "n" + strconv.Itoa(index)
				seen := benchSeen(name, after.Add(time.Duration(index)*apart), 0)
				key := detectionstate.Key{Tenant: tenant, Rule: rule, Group: name}
				if _, err := keeper.Observe(context.Background(), key, seen, within); err != nil {
					b.Fatalf("reclaim: %v", err)
				}
			}
		})
	}
}

// The one walk that does not follow from a key: a store at its own ceiling asks
// every tenant on every partition, so what it costs is measured against how many
// of them there are, once per refusal when each moves the stream a second and
// next to nothing when a flood sends them faster than that.
func BenchmarkRefuseANewKeyAtTheStoreCeiling(b *testing.B) {
	const partitions = 12

	for _, flood := range []struct {
		name    string
		tenants int
		apart   time.Duration
	}{
		{"sweeping/100", 100, time.Second},
		{"sweeping/1000", 1000, time.Second},
		{"paced/1000", 1000, time.Microsecond},
	} {
		tenants, apart := flood.tenants, flood.apart
		b.Run(flood.name, func(b *testing.B) {
			keeper, err := detectionstate.NewKeeper(detectionstate.Bounds{
				Window:             detectionstate.MaxWindow,
				ObservationsPerKey: 8,
				Keys:               millionKeys,
				KeysPerTenant:      min(millionKeys/tenants+1, millionKeys),
				KeysPerRule:        min(millionKeys/tenants+1, millionKeys),
			})
			if err != nil {
				b.Fatalf("bound the keeper: %v", err)
			}
			for index := range millionKeys {
				owner := "tenant-" + strconv.Itoa(index%tenants)
				partition := int32(index / tenants % partitions)
				seen := benchSeen(strconv.Itoa(index), epoch, partition)
				if _, err := keeper.Observe(context.Background(), benchKey(owner, index), seen, detectionstate.MaxWindow); err != nil {
					b.Fatalf("fill the keeper: %v", err)
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for index := range b.N {
				name := "n" + strconv.Itoa(index)
				key := detectionstate.Key{Tenant: "asking", Rule: rule, Group: name}
				seen := benchSeen(name, epoch.Add(time.Duration(index)*apart), 0)
				if _, err := keeper.Observe(context.Background(), key, seen, detectionstate.MaxWindow); err == nil {
					b.Fatal("a store with every key live took a new one")
				}
			}
		})
	}
}
