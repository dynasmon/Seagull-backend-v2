package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

// What a correlation key and a suppression selector may name. One vocabulary
// for both, so what an estate keys alerts by and what it suppresses them by are
// written the same way.
type Part string

const (
	PartRule     Part = "rule"
	PartAgent    Part = "agent"
	PartClass    Part = "class"
	PartSeverity Part = "severity"
)

const EvidencePrefix = "evidence:"

var parts = []Part{PartRule, PartAgent, PartClass, PartSeverity}

func Parts() []Part { return slices.Clone(parts) }

func (p Part) String() string { return string(p) }

func (p Part) Field() (string, bool) {
	field, evidence := strings.CutPrefix(string(p), EvidencePrefix)
	return field, evidence && field != ""
}

func (p Part) Valid() bool {
	if _, evidence := p.Field(); evidence {
		return true
	}
	return slices.Contains(parts, p)
}

func ParsePart(written string) (Part, error) {
	part := Part(strings.TrimSpace(written))
	if !part.Valid() {
		return "", fmt.Errorf("%q names nothing an alert can be keyed by; there are %s, or %s<field>",
			written, join(parts), EvidencePrefix)
	}
	return part, nil
}

// v1 chose the key by matching a prefix of the rule id — `ddos_` dropped the
// source and `ssh_bruteforce_` dropped the destination — so a rule renamed was a
// rule that stopped deduplicating. Here the estate declares it and a rule id is
// only ever compared for equality.
func (p Part) Of(made *detectionv1.Detection) (string, bool) {
	if field, evidence := p.Field(); evidence {
		for _, seen := range made.GetEvidence() {
			if seen.GetField() == field {
				return seen.GetHeld(), !seen.GetAbsent()
			}
		}
		return "", false
	}

	switch p {
	case PartRule:
		return made.GetRule().GetId(), made.GetRule().GetId() != ""
	case PartAgent:
		return made.GetOrigin().GetAgentId(), made.GetOrigin().GetAgentId() != ""
	case PartClass:
		return Class(made.GetEventClass()), made.GetEventClass() != 0
	case PartSeverity:
		return Severity(made.GetSeverity()), made.GetSeverity() != 0
	}
	return "", false
}

// Two detections sharing this are the same piece of work. The tenant is always
// in it and is never declared: an alert that could fold across a tenant boundary
// is a scope somebody could read past.
func CorrelationKey(made *detectionv1.Detection, keyed []Part) string {
	digest := sha256.New()
	write := func(value string) { fmt.Fprintf(digest, "%d:%s", len(value), value) }

	write(made.GetOrigin().GetTenantId())

	ordered := slices.Clone(keyed)
	slices.Sort(ordered)
	for _, part := range slices.Compact(ordered) {
		value, held := part.Of(made)
		write(part.String())
		if !held {
			write("\x00absent")
			continue
		}
		write(value)
	}
	return hex.EncodeToString(digest.Sum(nil)[:16])
}
