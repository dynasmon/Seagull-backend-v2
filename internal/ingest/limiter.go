package ingest

import (
	"container/list"
	"sync"

	"golang.org/x/time/rate"
)

// A per-instance budget, not a cluster-wide quota: it exists so that one noisy
// or captured agent cannot spend the whole gateway, and the tracked set is
// capped so that many distinct agent identities cannot exhaust memory either.
type Limiter struct {
	perSecond rate.Limit
	burst     int
	capacity  int

	mu      sync.Mutex
	order   *list.List
	buckets map[string]*list.Element
}

type bucketEntry struct {
	agentID string
	limiter *rate.Limiter
}

func NewLimiter(perSecond float64, burst, capacity int) *Limiter {
	return &Limiter{
		perSecond: rate.Limit(perSecond),
		burst:     burst,
		capacity:  capacity,
		order:     list.New(),
		buckets:   map[string]*list.Element{},
	}
}

func (l *Limiter) Allow(agentID string) bool {
	if l == nil || l.perSecond <= 0 {
		return true
	}

	l.mu.Lock()
	element, known := l.buckets[agentID]
	if known {
		l.order.MoveToFront(element)
	} else {
		element = l.order.PushFront(&bucketEntry{
			agentID: agentID,
			limiter: rate.NewLimiter(l.perSecond, l.burst),
		})
		l.buckets[agentID] = element
		l.evictLocked()
	}
	limiter := element.Value.(*bucketEntry).limiter
	l.mu.Unlock()

	return limiter.Allow()
}

func (l *Limiter) evictLocked() {
	for l.order.Len() > l.capacity {
		oldest := l.order.Back()
		if oldest == nil {
			return
		}
		l.order.Remove(oldest)
		delete(l.buckets, oldest.Value.(*bucketEntry).agentID)
	}
}

func (l *Limiter) Tracked() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
