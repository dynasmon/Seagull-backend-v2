package ruleset

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

// A rule published twice under one revision and meaning two different things.
// A detection is named by the rule and the revision that decided it, and so is
// the state a counting rule remembers, so the pair has to mean one thing for as
// long as the log lives or a replay rewrites what another rule found. Catalogue
// refuses one as it is read back and Admits answers before anything is written,
// where the author can still fix it.
type Conflict struct {
	Rule     detection.ID
	Revision int
}

func (c *Conflict) Error() string {
	return fmt.Sprintf("rule %q was already published at revision %d asking something else; a rule that changes takes the next revision",
		c.Rule, c.Revision)
}

// The key one line of the activation trail is kept under, named by what happened
// rather than by when it was written: an activation a retry publishes twice is
// one thing that happened, so compaction keeps one record of it and a reader
// that replays the log before compaction runs holds one line of it.
func ActivationKey(active *rulesetv1.Active) string {
	digest := sha256.New()
	write := func(value string) { fmt.Fprintf(digest, "%d:%s", len(value), value) }

	write(active.GetRulesetId())
	write(active.GetActivatedBy())
	write(active.GetActivatedAt().AsTime().UTC().Format(time.RFC3339Nano))
	write(active.GetNote())
	return "activated." + hex.EncodeToString(digest.Sum(nil)[:16])
}

// What has been published and which of it is meant to be running, built by
// applying the records of the published log in the order they were written. Two
// processes that have read the same log hold the same catalogue, which is what
// lets the control plane answer for a ruleset it does not run and an engine run
// one it was not told about directly.
type Catalogue struct {
	mu        sync.RWMutex
	versions  map[ID]*Version
	order     []ID
	active    *rulesetv1.Active
	activated []*rulesetv1.Active
	recorded  map[string]struct{}
	revisions map[revised]string
}

type revised struct {
	rule     detection.ID
	revision int
}

func NewCatalogue() *Catalogue {
	return &Catalogue{
		versions:  make(map[ID]*Version),
		recorded:  make(map[string]struct{}),
		revisions: make(map[revised]string),
	}
}

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
		if err := c.conflicting(version); err != nil {
			return err
		}
		c.versions[version.ID()] = version
		c.order = append(c.order, version.ID())
		for program := range version.snapshot.All() {
			rule := program.Rule()
			c.revisions[revised{rule: rule.ID, revision: rule.Revision}] = Fingerprint(program)
		}
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

func (c *Catalogue) Admits(version *Version) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conflicting(version)
}

func (c *Catalogue) conflicting(version *Version) error {
	for program := range version.snapshot.All() {
		rule := program.Rule()
		held, published := c.revisions[revised{rule: rule.ID, revision: rule.Revision}]
		if published && held != Fingerprint(program) {
			return &Conflict{Rule: rule.ID, Revision: rule.Revision}
		}
	}
	return nil
}

// A record read off the log, applied as the pointer or kept as a line of the
// trail. Which of the two an activation is comes from the key it was written
// under, and the key belongs to whatever carries the log rather than here. A
// line of the trail never moves the pointer: one replayed as desired state would
// activate a ruleset somebody had already rolled back. The lines are kept in the
// order the log carries them, which is the order they happened, so what an
// activation replaced is the line before it.
func (c *Catalogue) Read(value []byte, desired bool) error {
	var record rulesetv1.Record
	if err := proto.Unmarshal(value, &record); err != nil {
		return fmt.Errorf("a ruleset record could not be read: %w", err)
	}
	if activation, held := record.GetRecord().(*rulesetv1.Record_Active); held && !desired {
		return c.Trailed(activation.Active)
	}
	return c.Apply(&record)
}

func (c *Catalogue) Trailed(active *rulesetv1.Active) error {
	if active.GetRulesetId() == "" {
		return errors.New("an activation names the ruleset it activates")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := ActivationKey(active)
	if _, held := c.recorded[key]; held {
		return nil
	}
	c.recorded[key] = struct{}{}
	c.activated = append(c.activated, active)
	return nil
}

func (c *Catalogue) Activations() []*rulesetv1.Active {
	c.mu.RLock()
	defer c.mu.RUnlock()

	held := make([]*rulesetv1.Active, 0, len(c.activated))
	for _, one := range c.activated {
		held = append(held, proto.Clone(one).(*rulesetv1.Active))
	}
	return held
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
