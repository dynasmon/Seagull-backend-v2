package agentidentity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"
)

// What a listener keeps of the certificate a connection presented: its
// fingerprint and the instant it is valid from, and nothing it names.
type Certificate struct {
	Fingerprint string
	NotBefore   time.Time
}

func certificateOf(leaf *x509.Certificate) Certificate {
	digest := sha256.Sum256(leaf.Raw)
	return Certificate{Fingerprint: hex.EncodeToString(digest[:]), NotBefore: leaf.NotBefore}
}

// What the registry binds an agent to, as a listener is told it: the
// certificate in force and the one it replaced, by fingerprint alone.
type Binding struct {
	Fingerprint string
	IssuedAt    time.Time
	Replaced    string
	ReplacedAt  time.Time
}

type Standing int

const (
	Unbound Standing = iota + 1
	InForce
	Tolerated
	Unheard
	Replaced
)

var standings = map[Standing]string{
	Unbound:   "unbound",
	InForce:   "in_force",
	Tolerated: "tolerated",
	Unheard:   "unheard",
	Replaced:  "replaced",
}

func (s Standing) String() string {
	if named, known := standings[s]; known {
		return named
	}
	return fmt.Sprintf("standing(%d)", int(s))
}

func (s Standing) Admits() bool { return s == Unbound || s == InForce || s == Tolerated }

// A certificate valid from no earlier than the one in force is one this
// listener has not heard of yet, never one a renewal replaced: refusing it would
// cost an agent that renewed while the listener was behind. The replaced
// certificate is tolerated for tolerance after the later of its replacement and
// the moment the listener learned of it, zero when it read the binding back.
func (b Binding) Judge(presented Certificate, learned, now time.Time, tolerance time.Duration) Standing {
	switch {
	case b.Fingerprint == "":
		return Unbound
	case presented.Fingerprint == b.Fingerprint:
		return InForce
	case b.Replaced != "" && presented.Fingerprint == b.Replaced:
		if now.Before(later(b.ReplacedAt, learned).Add(tolerance)) {
			return Tolerated
		}
		return Replaced
	case b.IssuedAt.IsZero() || !presented.NotBefore.Before(b.IssuedAt):
		return Unheard
	}
	return Replaced
}

func later(one, other time.Time) time.Time {
	if other.After(one) {
		return other
	}
	return one
}

// A binding as a listener holds it: the record that said so, by its registry
// revision, and when the listener learned of it, zero for a record it read back
// before it served.
type Held struct {
	Binding  Binding
	Revision uint64
	Learned  time.Time
}

func (h Held) Judge(presented Certificate, now time.Time, tolerance time.Duration) Standing {
	return h.Binding.Judge(presented, h.Learned, now, tolerance)
}
