package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
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

var ErrUndeclaredField = errors.New("names a field the event contract does not declare, which no detection can ever hold")

var parts = []Part{PartRule, PartAgent, PartClass, PartSeverity}

func Parts() []Part { return slices.Clone(parts) }

func (p Part) String() string { return string(p) }

func (p Part) Field() (string, bool) {
	field, evidence := strings.CutPrefix(string(p), EvidencePrefix)
	return field, evidence && field != ""
}

func (p Part) Valid() bool { return p.refusal() == nil }

func (p Part) refusal() error {
	if field, evidence := p.Field(); evidence {
		if _, declared := detection.KindOf(detection.Field(field)); !declared {
			return ErrUndeclaredField
		}
		return nil
	}
	if !slices.Contains(parts, p) {
		return fmt.Errorf("names nothing an alert can be keyed by; there are %s, or %s<field>", join(parts), EvidencePrefix)
	}
	return nil
}

func ParsePart(written string) (Part, error) {
	part := Part(strings.TrimSpace(written))
	if err := part.refusal(); err != nil {
		return "", fmt.Errorf("%q %w", written, err)
	}
	return part, nil
}

// v1 chose the key by matching a prefix of the rule id — `ddos_` dropped the
// source and `ssh_bruteforce_` dropped the destination — so a rule renamed was a
// rule that stopped deduplicating. Here the estate declares it and a rule id is
// only ever compared for equality.
func (p Part) Of(made *detectionv1.Detection) (string, bool) {
	if field, evidence := p.Field(); evidence {
		return detection.HeldIn(made, detection.Field(field))
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

// A part the detection says nothing about holds the same for every detection of
// its rule, so it keeps none of them apart: the alerts it was declared to
// separate fold into one.
func Unspoken(made *detectionv1.Detection, keyed []Part) []Part {
	var unspoken []Part
	for _, part := range distinct(keyed) {
		if field, evidence := part.Field(); evidence && !detection.Speaks(made, detection.Field(field)) {
			unspoken = append(unspoken, part)
		}
	}
	return unspoken
}

// Two detections sharing this are the same piece of work. The tenant is always
// in it and is never declared: an alert that could fold across a tenant boundary
// is a scope somebody could read past.
func CorrelationKey(made *detectionv1.Detection, keyed []Part) string {
	digest := sha256.New()
	write := func(value string) { fmt.Fprintf(digest, "%d:%s", len(value), value) }

	write(made.GetOrigin().GetTenantId())

	for _, part := range distinct(keyed) {
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

func distinct(keyed []Part) []Part {
	ordered := slices.Clone(keyed)
	slices.Sort(ordered)
	return slices.Compact(ordered)
}
