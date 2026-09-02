package detectionstate

import (
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

	mu        sync.Mutex
	keys      map[Key]*held
	watermark time.Time
}

func NewKeeper(bounds Bounds) (*Keeper, error) {
	if err := bounds.Validate(); err != nil {
		return nil, err
	}
	return &Keeper{bounds: bounds, keys: make(map[Key]*held)}, nil
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

	if seen.At.After(k.watermark) {
		k.watermark = seen.At
	}

	entry, opened := k.keys[key]
	if !opened {
		if len(k.keys) >= k.bounds.Keys {
			k.reclaim()
		}
		if len(k.keys) >= k.bounds.Keys {
			return State{}, nil, ErrAtCapacity
		}
		entry = &held{ids: make(map[string]struct{})}
		k.keys[key] = entry
	}
	entry.window = window

	state, err := entry.observe(seen, k.bounds.ObservationsPerKey)
	if err != nil || !read {
		return state, nil, err
	}
	return state, slices.Clone(entry.seen), nil
}

func (k *Keeper) Keys() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.keys)
}

func (k *Keeper) Watermark() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.watermark
}

// Keys the stream has moved past, measured by a watermark that only ever moves
// forward, and only under pressure: nothing here runs a goroutine, and a store
// that is not full has no reason to walk itself.
func (k *Keeper) reclaim() int {
	gone := 0
	for key, entry := range k.keys {
		last := entry.last()
		if last.IsZero() || last.Before(k.watermark.Add(-entry.window)) {
			delete(k.keys, key)
			gone++
		}
	}
	return gone
}

type held struct {
	window time.Duration
	seen   []Observation
	ids    map[string]struct{}
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
