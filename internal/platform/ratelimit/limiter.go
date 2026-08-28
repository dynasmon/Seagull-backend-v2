// Package ratelimit holds one caller to a share of a process. It is
// infrastructure and not a policy: what a caller is, and what share they get,
// are decided by whoever builds the limiter.
package ratelimit

import (
	"container/list"
	"sync"

	"golang.org/x/time/rate"
)

// A per-instance budget, not a cluster-wide quota: it exists so that one noisy
// or captured caller cannot spend the whole process, and the tracked set is
// capped so that many distinct callers cannot exhaust memory either.
//
// What names a caller is the caller's business — an agent identity at the
// gateway, a certificate subject at the control plane. The budget is the same
// shape either way, which is why this is here and not inside one of them.
type Limiter struct {
	perSecond rate.Limit
	burst     int
	capacity  int

	mu      sync.Mutex
	order   *list.List
	buckets map[string]*list.Element
}

type bucketEntry struct {
	key     string
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

func (l *Limiter) Allow(key string) bool {
	if l == nil || l.perSecond <= 0 {
		return true
	}

	l.mu.Lock()
	element, known := l.buckets[key]
	if known {
		l.order.MoveToFront(element)
	} else {
		element = l.order.PushFront(&bucketEntry{
			key:     key,
			limiter: rate.NewLimiter(l.perSecond, l.burst),
		})
		l.buckets[key] = element
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
		delete(l.buckets, oldest.Value.(*bucketEntry).key)
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
