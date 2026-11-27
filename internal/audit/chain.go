package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
)

const (
	entryDomain = "seagull.audit.v1.Entry"
	digestSize  = sha256.Size
)

var (
	ErrSequenceGap      = errors.New("an audit chain skips a sequence")
	ErrPreviousMismatch = errors.New("an audit entry does not follow the digest before it")
	ErrDigestMismatch   = errors.New("an audit entry does not hold the digest of what it records")
	ErrOtherChain       = errors.New("an audit entry belongs to another chain")
)

// The bytes digested are written beside Entry in the contract, so a verifier in
// any language computes the same digest from the event as it was published.
func Digest(chain string, sequence uint64, previous []byte, event []byte) ([]byte, error) {
	if len(previous) != digestSize {
		return nil, fmt.Errorf("an audit entry follows a digest of %d bytes, not %d", len(previous), digestSize)
	}
	if len(chain) > math.MaxUint32 || len(event) > math.MaxUint32 {
		return nil, errors.New("an audit entry is too large to digest")
	}
	hash := sha256.New()
	hash.Write([]byte(entryDomain))
	hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(chain))))
	hash.Write([]byte(chain))
	hash.Write(binary.BigEndian.AppendUint64(nil, sequence))
	hash.Write(previous)
	hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(event))))
	hash.Write(event)
	return hash.Sum(nil), nil
}

// Chain is where one chain stands: the newest entry's sequence and digest. Its
// zero value is a chain with nothing on it.
type Chain struct {
	Name     string
	Sequence uint64
	Head     []byte
}

func (c Chain) head() []byte {
	if len(c.Head) == 0 {
		return make([]byte, digestSize)
	}
	return c.Head
}

// Append returns the entry the event becomes on this chain and the chain after it.
func (c Chain) Append(event []byte) (*auditv1.Entry, Chain, error) {
	previous := c.head()
	sequence := c.Sequence + 1
	digest, err := Digest(c.Name, sequence, previous, event)
	if err != nil {
		return nil, c, err
	}
	entry := &auditv1.Entry{Event: event, Chain: c.Name, Sequence: sequence, Previous: previous, Digest: digest}
	return entry, Chain{Name: c.Name, Sequence: sequence, Head: digest}, nil
}

// Verify follows entries, oldest first, from where the chain stood, and returns
// where they leave it. The first entry that does not follow is named with why.
func (c Chain) Verify(entries []*auditv1.Entry) (Chain, error) {
	at := c
	for _, entry := range entries {
		switch {
		case entry.GetChain() != at.Name:
			return at, fmt.Errorf("entry %d: %w", entry.GetSequence(), ErrOtherChain)
		case entry.GetSequence() != at.Sequence+1:
			return at, fmt.Errorf("entry %d after %d: %w", entry.GetSequence(), at.Sequence, ErrSequenceGap)
		case !bytes.Equal(entry.GetPrevious(), at.head()):
			return at, fmt.Errorf("entry %d: %w", entry.GetSequence(), ErrPreviousMismatch)
		}
		digest, err := Digest(entry.GetChain(), entry.GetSequence(), entry.GetPrevious(), entry.GetEvent())
		if err != nil {
			return at, fmt.Errorf("entry %d: %w", entry.GetSequence(), err)
		}
		if !bytes.Equal(digest, entry.GetDigest()) {
			return at, fmt.Errorf("entry %d: %w", entry.GetSequence(), ErrDigestMismatch)
		}
		at = Chain{Name: at.Name, Sequence: entry.GetSequence(), Head: digest}
	}
	return at, nil
}
