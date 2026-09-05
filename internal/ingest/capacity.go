package ingest

import (
	"errors"
	"sync"
)

// What the process will hold at once, counted in bytes rather than in requests
// alone. A body ceiling bounds one caller and nothing about it bounds the sum
// of them, and the sum is what exhausts a process.
type Capacity struct {
	bytes    int64
	requests int

	mu       sync.Mutex
	held     int64
	inflight int
}

var ErrNoCapacity = errors.New("a gateway holds a positive number of bytes and requests at once")

func NewCapacity(bytes int64, requests int) (*Capacity, error) {
	if bytes <= 0 || requests <= 0 {
		return nil, ErrNoCapacity
	}
	return &Capacity{bytes: bytes, requests: requests}, nil
}

// Reserved before the body is read, so the memory is accounted for before it
// is allocated rather than after.
func (c *Capacity) Hold(bytes int64) (func(), bool) {
	if c == nil {
		return func() {}, true
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight >= c.requests || c.held+bytes > c.bytes {
		return nil, false
	}
	c.held += bytes
	c.inflight++

	released := false
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if released {
			return
		}
		released = true
		c.held -= bytes
		c.inflight--
	}, true
}

func (c *Capacity) Held() (int64, int) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.held, c.inflight
}

func (c *Capacity) Bounds() (int64, int) {
	if c == nil {
		return 0, 0
	}
	return c.bytes, c.requests
}
