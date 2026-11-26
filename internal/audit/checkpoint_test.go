package audit_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/audit"
	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
)

func signer(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return private.Public().(ed25519.PublicKey), private
}

func TestACheckpointIsSignedOverTheBytesTheContractWritesAndVerifiedWithThePublicKey(t *testing.T) {
	public, private := signer(t, 1)
	_, chain := chained(t, "tenant-a", "first", "second")
	at := time.Date(2026, time.November, 25, 12, 0, 0, 500, time.UTC)

	first, err := audit.Seal(chain, 0, nil, at, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.VerifyCheckpoint(first, public, nil); err != nil {
		t.Fatalf("a checkpoint does not verify with the key that signed it: %v", err)
	}
	signed, err := audit.SignedBytes(first)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(signed[:27]); got != hex.EncodeToString([]byte("seagull.audit.v1.Checkpoint")) {
		t.Errorf("the signed bytes start with %s", got)
	}
	if len(signed) != 27+4+len("tenant-a")+8+8+32+8+4+32+32 {
		t.Errorf("the signed bytes are %d long", len(signed))
	}

	digest, err := audit.CheckpointDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(signed)
	if !bytes.Equal(digest, sum[:]) {
		t.Errorf("a checkpoint's digest is not the SHA-256 of its signed bytes")
	}
	second, err := audit.Seal(chain, 0, digest, at.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.VerifyCheckpoint(second, public, digest); err != nil {
		t.Fatalf("a checkpoint after another does not verify: %v", err)
	}
	if err := audit.VerifyCheckpoint(second, public, nil); !errors.Is(err, audit.ErrCheckpointOrder) {
		t.Errorf("a checkpoint whose predecessor was removed verified as %v", err)
	}
}

func TestEveryFieldOfACheckpointIsSigned(t *testing.T) {
	public, private := signer(t, 2)
	_, chain := chained(t, "tenant-a", "first", "second", "third")
	sealed, err := audit.Seal(chain, 1, nil, time.Unix(1_800_000_000, 0), private)
	if err != nil {
		t.Fatal(err)
	}
	for name, tamper := range map[string]func(*auditv1.Checkpoint){
		"the chain":          func(c *auditv1.Checkpoint) { c.Chain = "tenant-b" },
		"the sequence":       func(c *auditv1.Checkpoint) { c.Sequence = 4 },
		"the digest":         func(c *auditv1.Checkpoint) { c.Digest = bytes.Repeat([]byte{1}, 32) },
		"the pruned range":   func(c *auditv1.Checkpoint) { c.PrunedThrough = 2 },
		"the signing second": func(c *auditv1.Checkpoint) { c.SignedAt = timestamppb.New(time.Unix(1_800_000_001, 0)) },
		"the signing nanos":  func(c *auditv1.Checkpoint) { c.SignedAt = timestamppb.New(time.Unix(1_800_000_000, 1)) },
		"the signature":      func(c *auditv1.Checkpoint) { c.Signature[0] ^= 1 },
	} {
		forged := proto.Clone(sealed).(*auditv1.Checkpoint)
		tamper(forged)
		if err := audit.VerifyCheckpoint(forged, public, nil); !errors.Is(err, audit.ErrCheckpointSignature) {
			t.Errorf("a checkpoint with %s changed verified as %v", name, err)
		}
	}
	other, _ := signer(t, 3)
	if err := audit.VerifyCheckpoint(sealed, other, nil); !errors.Is(err, audit.ErrCheckpointKey) {
		t.Errorf("a checkpoint verified against another key as %v", err)
	}
}

func TestAPrunedRangeIsSealedSoTheRestOfTheChainStillVerifies(t *testing.T) {
	public, private := signer(t, 4)
	entries, end := chained(t, "tenant-a", "first", "second", "third", "fourth")
	through, err := (audit.Chain{Name: "tenant-a"}).Verify(entries[:2])
	if err != nil {
		t.Fatal(err)
	}
	seal, err := audit.Seal(through, through.Sequence, nil, time.Now(), private)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.VerifyCheckpoint(seal, public, nil); err != nil {
		t.Fatal(err)
	}
	at, err := audit.From(seal).Verify(entries[2:])
	if err != nil || at.Sequence != end.Sequence || !bytes.Equal(at.Head, end.Head) {
		t.Fatalf("what is left after pruning does not verify from the seal: %v", err)
	}
	if _, err := audit.From(seal).Verify(entries[3:]); !errors.Is(err, audit.ErrSequenceGap) {
		t.Errorf("an entry removed after the seal verified as %v", err)
	}
	if _, err := audit.Seal(through, through.Sequence+1, nil, time.Now(), private); err == nil {
		t.Error("a checkpoint sealed a range past where its chain stands")
	}
}
