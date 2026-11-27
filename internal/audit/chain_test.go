package audit_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/audit"
	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
)

func chained(t *testing.T, name string, events ...string) ([]*auditv1.Entry, audit.Chain) {
	t.Helper()
	chain := audit.Chain{Name: name}
	entries := make([]*auditv1.Entry, 0, len(events))
	for _, event := range events {
		entry, next, err := chain.Append([]byte(event))
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		entries = append(entries, entry)
		chain = next
	}
	return entries, chain
}

func TestAnEntryIsDigestedAsTheContractWritesIt(t *testing.T) {
	previous := bytes.Repeat([]byte{0xab}, 32)
	digest, err := audit.Digest("tenant-a", 7, previous, []byte("event"))
	if err != nil {
		t.Fatal(err)
	}
	written := []byte("seagull.audit.v1.Entry")
	written = binary.BigEndian.AppendUint32(written, 8)
	written = append(written, "tenant-a"...)
	written = binary.BigEndian.AppendUint64(written, 7)
	written = append(written, previous...)
	written = binary.BigEndian.AppendUint32(written, 5)
	written = append(written, "event"...)
	want := sha256.Sum256(written)
	if !bytes.Equal(digest, want[:]) {
		t.Fatalf("the digest is %x, and the contract's encoding digests to %x", digest, want)
	}
	if got := hex.EncodeToString(digest); got != "941b477024765b4ffe51e4a3834cc1810a4aa82d904609fde5eb3ae731bcc760" {
		t.Errorf("the fixed vector a verifier in another language is held to digests to %s", got)
	}
}

func TestAChainVerifiesFromItsStartAndNamesTheFirstEntryThatDoesNotFollow(t *testing.T) {
	entries, end := chained(t, "tenant-a", "first", "second", "third")
	if entries[0].GetSequence() != 1 || !bytes.Equal(entries[0].GetPrevious(), make([]byte, 32)) {
		t.Fatalf("a chain starts at %d after %x", entries[0].GetSequence(), entries[0].GetPrevious())
	}
	at, err := audit.Chain{Name: "tenant-a"}.Verify(entries)
	if err != nil || at.Sequence != end.Sequence || !bytes.Equal(at.Head, end.Head) {
		t.Fatalf("a chain written by Append does not verify: %v", err)
	}

	clone := func() []*auditv1.Entry {
		copied := make([]*auditv1.Entry, len(entries))
		for i, entry := range entries {
			copied[i] = &auditv1.Entry{Event: entry.Event, Chain: entry.Chain, Sequence: entry.Sequence, Previous: entry.Previous, Digest: entry.Digest}
		}
		return copied
	}
	for name, case_ := range map[string]struct {
		tamper func([]*auditv1.Entry) []*auditv1.Entry
		want   error
	}{
		"an altered event":     {func(e []*auditv1.Entry) []*auditv1.Entry { e[1].Event = []byte("forged"); return e }, audit.ErrDigestMismatch},
		"a removed entry":      {func(e []*auditv1.Entry) []*auditv1.Entry { return append(e[:1], e[2]) }, audit.ErrSequenceGap},
		"two entries swapped":  {func(e []*auditv1.Entry) []*auditv1.Entry { e[1], e[2] = e[2], e[1]; return e }, audit.ErrSequenceGap},
		"a renumbered removal": {func(e []*auditv1.Entry) []*auditv1.Entry { e[2].Sequence = 2; return append(e[:1], e[2]) }, audit.ErrPreviousMismatch},
		"another chain's":      {func(e []*auditv1.Entry) []*auditv1.Entry { e[2].Chain = "tenant-b"; return e }, audit.ErrOtherChain},
	} {
		if _, err := (audit.Chain{Name: "tenant-a"}).Verify(case_.tamper(clone())); !errors.Is(err, case_.want) {
			t.Errorf("%s verified as %v, want %v", name, err, case_.want)
		}
	}
}

func TestTheChainOfWhatBelongsToNoTenantIsAChainOfItsOwn(t *testing.T) {
	platform, _ := chained(t, "", "a ruleset published")
	tenant, _ := chained(t, "tenant-a", "a ruleset published")
	if bytes.Equal(platform[0].GetDigest(), tenant[0].GetDigest()) {
		t.Error("one event on two chains has one digest, so an entry could be moved between them unseen")
	}
}
