package hunt

import (
	"errors"
	"sync"
)

// How many questions this process will hold against the store at once. The
// store's own pool bounds what it will run and nothing bounds what waits for a
// connection, so a caller with a valid certificate can queue enough work to make
// every other analyst wait behind it. A refusal now is worth more to them than a
// place in a queue nobody is still waiting on.
type Capacity struct {
	ceiling int

	mu       sync.Mutex
	inflight int
}

func NewCapacity(ceiling int) (*Capacity, error) {
	if ceiling <= 0 {
		return nil, errors.New("a query plane holds a positive number of questions at once")
	}
	return &Capacity{ceiling: ceiling}, nil
}

func (c *Capacity) Hold() (func(), bool) {
	if c == nil {
		return func() {}, true
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight >= c.ceiling {
		return nil, false
	}
	c.inflight++

	released := false
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if released {
			return
		}
		released = true
		c.inflight--
	}, true
}

func (c *Capacity) Held() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inflight
}

func (c *Capacity) Ceiling() int {
	if c == nil {
		return 0
	}
	return c.ceiling
}
