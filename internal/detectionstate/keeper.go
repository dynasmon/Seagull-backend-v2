package detectionstate

import (
	"container/heap"
	"context"
	"slices"
	"sort"
	"sync"
	"time"
)

var _ Store = (*Keeper)(nil)

// State held by the process that decided the event. A consumer group gives one
// process a partition, so a key whose group stays inside one agent needs no
// coordination beyond this lock.
type Keeper struct {
	bounds Bounds

	mu      sync.Mutex
	keys    map[Key]*held
	tenants map[string]*tenantKeys
	newest  time.Time
	swept   time.Time
}

func NewKeeper(bounds Bounds) (*Keeper, error) {
	if err := bounds.Validate(); err != nil {
		return nil, err
	}
	return &Keeper{bounds: bounds, keys: make(map[Key]*held), tenants: make(map[string]*tenantKeys)}, nil
}

// An event already folded answers what the key already held, and every window
// is event time, so the state is a pure function of the events inside it: the
// same stream replayed rebuilds it, which is the whole restart strategy.
func (k *Keeper) Observe(ctx context.Context, key Key, seen Observation, window time.Duration) (State, error) {
	state, _, err := k.fold(ctx, key, seen, window, false)
	return state, err
}

func (k *Keeper) Ordered(ctx context.Context, key Key, seen Observation, window time.Duration) (State, []Observation, error) {
	return k.fold(ctx, key, seen, window, true)
}

func (k *Keeper) fold(ctx context.Context, key Key, seen Observation, window time.Duration, read bool) (State, []Observation, error) {
	if err := ctx.Err(); err != nil {
		return State{}, nil, err
	}
	if err := seen.Validate(); err != nil {
		return State{}, nil, err
	}
	switch {
	case window <= 0:
		return State{}, nil, ErrNoWindow
	case window > k.bounds.Window:
		return State{}, nil, ErrWindowTooLong
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	k.advance(key.Tenant, seen)

	entry, opened := k.keys[key]
	if !opened {
		if err := k.admit(key); err != nil {
			return State{}, nil, err
		}
		entry = &held{key: key, ids: make(map[EventName]struct{})}
	}
	entry.window = window

	state, err := entry.observe(seen, k.bounds.ObservationsPerKey)
	if !opened {
		k.open(entry, seen)
	}
	if err != nil || !read {
		return state, nil, err
	}
	return state, slices.Clone(entry.seen), nil
}

func (k *Keeper) advance(tenant string, seen Observation) {
	if seen.At.After(k.newest) {
		k.newest = seen.At
	}
	if owner := k.tenants[tenant]; owner != nil {
		if keys := owner.partitions[seen.Partition]; keys != nil {
			keys.delivered(seen.At, k.newest)
		}
	}
}

func (k *Keeper) admit(key Key) error {
	if owner := k.tenants[key.Tenant]; owner != nil {
		if owner.refuses(key.Rule, k.bounds) != nil || len(k.keys) >= k.bounds.Keys {
			k.reclaim(owner)
		}
		if err := owner.refuses(key.Rule, k.bounds); err != nil {
			return err
		}
	}
	if len(k.keys) >= k.bounds.Keys {
		k.sweep()
	}
	if len(k.keys) >= k.bounds.Keys {
		return ErrAtCapacity
	}
	return nil
}

func (k *Keeper) open(entry *held, seen Observation) {
	owner := k.tenants[entry.key.Tenant]
	if owner == nil {
		owner = newTenantKeys(entry.key.Tenant)
		k.tenants[entry.key.Tenant] = owner
	}
	entry.key.Tenant = owner.tenant
	keys := owner.partitions[seen.Partition]
	if keys == nil {
		keys = &partitionKeys{watermark: seen.At, heard: k.newest}
		owner.partitions[seen.Partition] = keys
	}

	owner.opened(entry.key.Rule)
	k.keys[entry.key] = entry
	heap.Push(&keys.expiring, entry)
}

func (k *Keeper) Keys() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.keys)
}

func (k *Keeper) Watermark(tenant string, partition int32) time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()

	if owner := k.tenants[tenant]; owner != nil {
		if keys := owner.partitions[partition]; keys != nil {
			return keys.watermark
		}
	}
	return time.Time{}
}

type held struct {
	key    Key
	window time.Duration
	seen   []Observation
	ids    map[EventName]struct{}
	values map[string]int
}

func (h *held) observe(seen Observation, ceiling int) (State, error) {
	if _, folded := h.ids[seen.Event]; folded {
		repeated := h.state(ceiling)
		repeated.Repeated = true
		return repeated, nil
	}

	newest := seen.At
	if last := h.last(); last.After(newest) {
		newest = last
	}
	cutoff := newest.Add(-h.window)
	h.expire(cutoff)

	if seen.At.Before(cutoff) {
		return h.state(ceiling), ErrTooLate
	}

	h.insert(seen)
	for len(h.seen) > ceiling {
		h.discard(0)
	}
	return h.state(ceiling), nil
}

// Kept in event time, not arrival order, so a sequence reads what happened
// rather than what the backbone delivered first.
func (h *held) insert(seen Observation) {
	at := sort.Search(len(h.seen), func(index int) bool { return h.seen[index].At.After(seen.At) })
	h.seen = slices.Insert(h.seen, at, seen)
	h.ids[seen.Event] = struct{}{}

	if seen.Value == "" {
		return
	}
	if h.values == nil {
		h.values = make(map[string]int)
	}
	h.values[seen.Value]++
}

func (h *held) expire(cutoff time.Time) {
	for len(h.seen) > 0 && h.seen[0].At.Before(cutoff) {
		h.discard(0)
	}
}

func (h *held) discard(index int) {
	gone := h.seen[index]
	h.seen = slices.Delete(h.seen, index, index+1)
	delete(h.ids, gone.Event)

	if gone.Value == "" {
		return
	}
	if h.values[gone.Value]--; h.values[gone.Value] <= 0 {
		delete(h.values, gone.Value)
	}
}

func (h *held) last() time.Time {
	if len(h.seen) == 0 {
		return time.Time{}
	}
	return h.seen[len(h.seen)-1].At
}

func (h *held) expires() time.Time { return h.last().Add(h.window) }

func (h *held) state(ceiling int) State {
	if len(h.seen) == 0 {
		return State{}
	}
	return State{
		First:     h.seen[0].At,
		Last:      h.last(),
		Count:     len(h.seen),
		Distinct:  len(h.values),
		Saturated: len(h.seen) >= ceiling,
	}
}
