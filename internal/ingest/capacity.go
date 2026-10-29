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

// What one request holds of the capacity: reserved before its body is read, so
// the memory is accounted for before it is allocated rather than after, and
// resized once the body is weighed, before it is decoded.
type Reservation struct {
	capacity *Capacity
	bytes    int64
	released bool
}

func (c *Capacity) Hold(bytes int64) (*Reservation, bool) {
	if c == nil {
		return &Reservation{}, true
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight >= c.requests || c.held+bytes > c.bytes {
		return nil, false
	}
	c.held += bytes
	c.inflight++
	return &Reservation{capacity: c, bytes: bytes}, true
}

func (r *Reservation) Resize(bytes int64) bool {
	c := r.capacity
	if c == nil {
		return true
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if r.released || c.held-r.bytes+bytes > c.bytes {
		return false
	}
	c.held += bytes - r.bytes
	r.bytes = bytes
	return true
}

func (r *Reservation) Release() {
	c := r.capacity
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if r.released {
		return
	}
	r.released = true
	c.held -= r.bytes
	c.inflight--
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
