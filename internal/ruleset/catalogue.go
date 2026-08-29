package ruleset

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

// What has been published and which of it is meant to be running, built by
// applying the records of the published log in the order they were written. Two
// processes that have read the same log hold the same catalogue, which is what
// lets the control plane answer for a ruleset it does not run and an engine run
// one it was not told about directly.
type Catalogue struct {
	mu       sync.RWMutex
	versions map[ID]*Version
	order    []ID
	active   *rulesetv1.Active
}

func NewCatalogue() *Catalogue { return &Catalogue{versions: make(map[ID]*Version)} }

// An activation naming a version this catalogue has not seen is kept rather
// than refused, so replaying a log never loses a pointer; the version it names
// becomes readable the moment its own record arrives.
func (c *Catalogue) Apply(record *rulesetv1.Record) error {
	switch held := record.GetRecord().(type) {
	case *rulesetv1.Record_Version:
		version, err := DecodeVersion(held.Version)
		if err != nil {
			return err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, published := c.versions[version.ID()]; published {
			return nil
		}
		c.versions[version.ID()] = version
		c.order = append(c.order, version.ID())
		return nil

	case *rulesetv1.Record_Active:
		if held.Active.GetRulesetId() == "" {
			return errors.New("an activation names the ruleset it activates")
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.active = held.Active
		return nil

	default:
		return errors.New("a ruleset record carries nothing this build can read")
	}
}

func (c *Catalogue) Read(value []byte) error {
	var record rulesetv1.Record
	if err := proto.Unmarshal(value, &record); err != nil {
		return fmt.Errorf("a ruleset record could not be read: %w", err)
	}
	return c.Apply(&record)
}

func (c *Catalogue) Versions() []*Version {
	c.mu.RLock()
	defer c.mu.RUnlock()

	held := make([]*Version, 0, len(c.order))
	for _, id := range c.order {
		held = append(held, c.versions[id])
	}
	return held
}

func (c *Catalogue) Version(id ID) (*Version, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	version, published := c.versions[id]
	return version, published
}

func (c *Catalogue) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.order)
}

func (c *Catalogue) Active() (*Version, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.active == nil {
		return nil, false
	}
	version, published := c.versions[ID(c.active.GetRulesetId())]
	return version, published
}

// Cloned rather than handed out, because what a catalogue holds is the log's
// and a reader that could write into it would be changing what every other
// reader of the same catalogue sees.
func (c *Catalogue) Activation() *rulesetv1.Active {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.active == nil {
		return nil
	}
	return proto.Clone(c.active).(*rulesetv1.Active)
}

func (c *Catalogue) Published(id ID) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, published := c.versions[id]
	return published
}

func (c *Catalogue) Order() []ID {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return slices.Clone(c.order)
}
