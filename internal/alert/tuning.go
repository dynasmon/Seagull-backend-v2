package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

var (
	ErrUnkeyed     = errors.New("a correlation key that does not name the rule folds two different rules into one alert")
	ErrNoReason    = errors.New("a suppression hides activity and has to say why")
	ErrNegative    = errors.New("a window and a cooldown are never negative")
	ErrNoSelection = errors.New("a suppression that selects nothing suppresses everything")
)

// How alerts for one rule are folded together. A window bounds how stale an open
// alert may be and still absorb what arrives; a cooldown bounds how soon after
// one was closed another may be raised. Both are measured in event time.
type Fold struct {
	Keyed    []Part
	Window   time.Duration
	Cooldown time.Duration
}

// Which detections never become work, and why. `Until` is what keeps a
// suppression from outliving the reason it was written for, which is the
// mistake an estate makes once.
type Suppression struct {
	Rule   string
	When   Selector
	Reason string
	Until  time.Time
}

type Selector map[Part][]string

func (s Selector) Matches(made *detectionv1.Detection) bool {
	for part, allowed := range s {
		value, held := part.Of(made)
		if !held || !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

// What a process is pinned to, named by its own content so two processes running
// the same document agree about it and a reload that changes nothing is visible
// as changing nothing.
type Tuning struct {
	id           string
	defaults     Fold
	byRule       map[string]Fold
	suppressions []Suppression
}

func NewTuning(defaults Fold, byRule map[string]Fold, suppressions []Suppression) (*Tuning, error) {
	if err := valid(defaults); err != nil {
		return nil, fmt.Errorf("the default fold is invalid: %w", err)
	}
	for rule, fold := range byRule {
		if err := valid(fold); err != nil {
			return nil, fmt.Errorf("the fold for %q is invalid: %w", rule, err)
		}
	}
	for index, suppression := range suppressions {
		if strings.TrimSpace(suppression.Reason) == "" {
			return nil, fmt.Errorf("suppression %d: %w", index+1, ErrNoReason)
		}
		if suppression.Rule == "" && len(suppression.When) == 0 {
			return nil, fmt.Errorf("suppression %d: %w", index+1, ErrNoSelection)
		}
	}

	tuning := &Tuning{
		defaults:     defaults,
		byRule:       maps.Clone(byRule),
		suppressions: slices.Clone(suppressions),
	}
	tuning.id = tuning.identify()
	return tuning, nil
}

func valid(fold Fold) error {
	if fold.Window < 0 || fold.Cooldown < 0 {
		return ErrNegative
	}
	if !slices.Contains(fold.Keyed, PartRule) {
		return ErrUnkeyed
	}
	for _, part := range fold.Keyed {
		if !part.Valid() {
			return fmt.Errorf("%q names nothing an alert can be keyed by", part)
		}
	}
	return nil
}

func (t *Tuning) ID() string { return t.id }

func (t *Tuning) Rules() int { return len(t.byRule) }

func (t *Tuning) Suppressions() int { return len(t.suppressions) }

func (t *Tuning) Fold(rule string) Fold {
	if fold, declared := t.byRule[rule]; declared {
		return fold
	}
	return t.defaults
}

// The first suppression that matches, so the document is read top to bottom and
// an expired one is stepped over rather than removed: an estate learns what it
// used to suppress by reading the file it still has.
func (t *Tuning) Suppressed(made *detectionv1.Detection, at time.Time) (Suppression, bool) {
	for _, suppression := range t.suppressions {
		if suppression.Rule != "" && suppression.Rule != made.GetRule().GetId() {
			continue
		}
		if !suppression.Until.IsZero() && !at.Before(suppression.Until) {
			continue
		}
		if suppression.When.Matches(made) {
			return suppression, true
		}
	}
	return Suppression{}, false
}

func (t *Tuning) identify() string {
	digest := sha256.New()
	write := func(value string) { fmt.Fprintf(digest, "%d:%s", len(value), value) }

	writeFold := func(name string, fold Fold) {
		write(name)
		keyed := slices.Clone(fold.Keyed)
		slices.Sort(keyed)
		for _, part := range keyed {
			write(part.String())
		}
		write(fold.Window.String())
		write(fold.Cooldown.String())
	}

	writeFold("", t.defaults)
	for _, rule := range slices.Sorted(maps.Keys(t.byRule)) {
		writeFold(rule, t.byRule[rule])
	}
	for _, suppression := range t.suppressions {
		write(suppression.Rule)
		write(suppression.Reason)
		write(suppression.Until.UTC().Format(time.RFC3339))
		for _, part := range slices.Sorted(maps.Keys(suppression.When)) {
			write(part.String())
			values := slices.Clone(suppression.When[part])
			sort.Strings(values)
			for _, value := range values {
				write(value)
			}
		}
	}
	return hex.EncodeToString(digest.Sum(nil)[:16])
}
