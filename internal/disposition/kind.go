package disposition

import vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"

// Kept by name rather than by the contract's number, so a store reads as what a
// person decided.
type Kind string

const (
	Ignored      Kind = "ignored"
	AcceptedRisk Kind = "accepted_risk"
)

var wire = map[Kind]vulnerabilityv1.DispositionKind{
	Ignored:      vulnerabilityv1.DispositionKind_DISPOSITION_KIND_IGNORED,
	AcceptedRisk: vulnerabilityv1.DispositionKind_DISPOSITION_KIND_ACCEPTED_RISK,
}

func KindOf(value vulnerabilityv1.DispositionKind) (Kind, bool) {
	for kind, written := range wire {
		if written == value {
			return kind, true
		}
	}
	return "", false
}

func (k Kind) Wire() vulnerabilityv1.DispositionKind { return wire[k] }

func (k Kind) String() string { return string(k) }
