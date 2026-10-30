package detectionstate

import (
	"container/heap"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

const sweepEvery = time.Second

// What one tenant holds: what its quotas are counted against, and everything its
// own pressure may reclaim. Nothing here is shared between tenants, so what a
// tenant sends moves no count, watermark or queue of another's.
type tenantKeys struct {
	tenant     string
	held       int
	rules      map[detection.ID]int
	partitions map[int32]*partitionKeys
}

func newTenantKeys(tenant string) *tenantKeys {
	return &tenantKeys{tenant: tenant, rules: make(map[detection.ID]int), partitions: make(map[int32]*partitionKeys)}
}

func (t *tenantKeys) refuses(rule detection.ID, bounds Bounds) error {
	switch {
	case t.held >= bounds.KeysPerTenant:
		return ErrTenantAtCapacity
	case t.rules[rule] >= bounds.KeysPerRule:
		return ErrRuleAtCapacity
	}
	return nil
}

func (t *tenantKeys) opened(rule detection.ID) {
	t.held++
	t.rules[rule]++
}

func (t *tenantKeys) closed(rule detection.ID) {
	t.held--
	if t.rules[rule]--; t.rules[rule] <= 0 {
		delete(t.rules, rule)
	}
}

// What one tenant holds of one partition, soonest past first, and how far that
// partition has taken it. While it delivers that is its own watermark, so one
// read back or behind keeps what it is still reading. Once it stops, because it
// went quiet or this process lost it, the rest of the stream carries it on from
// where it stopped, and its keys go past their windows like any other instead of
// holding their tenant's room for good. A key stays with the partition that
// opened it, the only one feeding it under a rule the stream keeps together; a
// key a sole reader holds across partitions is timed by the first of them.
type partitionKeys struct {
	watermark time.Time
	heard     time.Time
	expiring  expiryIndex
}

func (p *partitionKeys) delivered(at, newest time.Time) {
	if at.After(p.watermark) {
		p.watermark = at
	}
	p.heard = newest
}

func (p *partitionKeys) clock(newest time.Time) time.Time {
	return p.watermark.Add(newest.Sub(p.heard))
}

type expiry struct {
	at    time.Time
	entry *held
}

type expiryIndex []expiry

func (x expiryIndex) Len() int { return len(x) }

func (x expiryIndex) Less(i, j int) bool { return x[i].at.Before(x[j].at) }

func (x expiryIndex) Swap(i, j int) { x[i], x[j] = x[j], x[i] }

func (x *expiryIndex) Push(value any) {
	entry := value.(*held)
	*x = append(*x, expiry{at: entry.expires(), entry: entry})
}

func (x *expiryIndex) Pop() any {
	last := len(*x) - 1
	entry := (*x)[last].entry
	(*x)[last] = expiry{}
	*x = (*x)[:last]
	return entry
}

// Keys the stream has moved past, and only under pressure: nothing here runs a
// goroutine, and a store with room has no reason to walk itself. A key past its
// window can only be read again by an event out of order, so reclaiming one costs
// a count that starts again, and only the tenant asking for room may pay it; the
// store's own ceiling is what asks of every tenant.
//
// A place in the queue is the first moment a key could be past, and a key only
// ever moves later. Folding leaves the queue alone, so a store with room pays
// nothing for it, and a key observed since it was filed is filed again here.
func (k *Keeper) reclaim(owner *tenantKeys) {
	for partition, keys := range owner.partitions {
		clock := keys.clock(k.newest)
		for len(keys.expiring) > 0 && keys.expiring[0].at.Before(clock) {
			entry := keys.expiring[0].entry
			if at := entry.expires(); !at.Before(clock) {
				keys.expiring[0].at = at
				heap.Fix(&keys.expiring, 0)
				continue
			}
			heap.Pop(&keys.expiring)
			delete(k.keys, entry.key)
			owner.closed(entry.key.Rule)
		}
		if len(keys.expiring) == 0 {
			delete(owner.partitions, partition)
		}
	}
	if owner.held == 0 {
		delete(k.tenants, owner.tenant)
	}
}

// What a store at its own ceiling asks of everyone, walking every tenant on every
// partition. A flood reaches this on every event it sends, so it runs once a
// second of the stream however often it is asked: a key gone past since then is
// refused room for that second at most, and never miscounted.
func (k *Keeper) sweep() {
	if k.newest.Sub(k.swept) < sweepEvery {
		return
	}
	k.swept = k.newest
	for _, owner := range k.tenants {
		k.reclaim(owner)
	}
}
