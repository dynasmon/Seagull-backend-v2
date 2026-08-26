package detection

import (
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// What makes an event worth telling somebody about, and what to tell them.
//
// A rule decides on one event at a time, from what that event carries and
// nothing else. Counting, windows, thresholds and cooldowns are not here: they
// are state, they arrive with aggregation, and a model that mixes them in from
// the start cannot say which of its rules are deterministic.
type Rule struct {
	// Stable across every revision of the rule, and never carrying a version:
	// v1 named a rule `ssh_bruteforce_authlog_v2` and then could not tell the
	// second version of a rule from a second rule.
	ID       ID
	Revision int

	Name        string
	Description string

	// The class decides which events ever reach the rule, so it is structural
	// rather than another predicate: the engine routes by class, and a rule is
	// registered on the route rather than asked about every event on the
	// backbone.
	Class eventv1.EventClass
	Match Expression

	Severity  Severity
	Status    Status
	Technique Technique

	// What an analyst is owed when this fires. v1 carried both and they were
	// the difference between an alert somebody could act on and one they could
	// only look at.
	FalsePositives string
	Response       string

	// Where the rule came from, what it is filed under, and what explains it.
	// None of the three changes what the rule decides, and all of them change
	// what somebody can do with a detection after it is made.
	Source     Source
	Tags       []string
	References []string
}

// Where a rule came from and what it was called there. Empty means this estate
// wrote it; a rule translated out of an upstream catalogue names the catalogue
// and keeps the identifier it had, so a detection can be traced past the rule to
// the thing the rule was made from and a later import can find it again. All of
// it or none of it, for the same reason half a technique is refused.
type Source struct {
	Catalogue  string // `sigma`
	Identifier string // what the rule was called there
}

func (s Source) empty() bool { return s.Catalogue == "" && s.Identifier == "" }

// Lowercase, and readable as a sentence about what is detected rather than as
// an identifier of the file it lives in.
type ID string

type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Where the rule is in its life. One axis, not two: v1 carried `status` and
// `enabled` and had to decide what an active rule that was disabled meant.
type Status string

const (
	Draft      Status = "draft"
	Active     Status = "active"
	Disabled   Status = "disabled"
	Deprecated Status = "deprecated"
)

// Runs is what the platform does with a rule: only an active one is evaluated.
// A draft is written, a disabled one is kept and not run, a deprecated one is
// kept so that what it once found can still be explained.
func (s Status) Runs() bool { return s == Active }

// Where the rule sits in ATT&CK. Optional — a hygiene rule need not attribute
// itself to an adversary technique — but all of it or none of it, because a
// tactic with no technique is a claim nobody can follow.
type Technique struct {
	Tactic string // `credential_access`
	ID     string // `T1110.001`
	Name   string // `Brute Force: Password Guessing`
}

func (t Technique) empty() bool {
	return t.Tactic == "" && t.ID == "" && t.Name == ""
}

// Every severity a rule may carry, and the one it is reported as when a
// detection leaves the process. One map rather than two, so a severity the
// platform cannot report is a severity a rule cannot be written with, and
// neither list can drift from the other.
var severities = map[Severity]detectionv1.Severity{
	Low:      detectionv1.Severity_SEVERITY_LOW,
	Medium:   detectionv1.Severity_SEVERITY_MEDIUM,
	High:     detectionv1.Severity_SEVERITY_HIGH,
	Critical: detectionv1.Severity_SEVERITY_CRITICAL,
}

var statuses = map[Status]struct{}{
	Draft: {}, Active: {}, Disabled: {}, Deprecated: {},
}

// The enterprise tactics, named as ATT&CK orders them. A closed set because a
// misspelled tactic is a rule that disappears from every view built on it, and
// the list changes about once a year.
var tactics = map[string]struct{}{
	"reconnaissance":       {},
	"resource_development": {},
	"initial_access":       {},
	"execution":            {},
	"persistence":          {},
	"privilege_escalation": {},
	"defense_evasion":      {},
	"credential_access":    {},
	"discovery":            {},
	"lateral_movement":     {},
	"collection":           {},
	"command_and_control":  {},
	"exfiltration":         {},
	"impact":               {},
}
