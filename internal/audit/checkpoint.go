package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
)

const checkpointDomain = "seagull.audit.v1.Checkpoint"

var (
	ErrCheckpointKey       = errors.New("an audit checkpoint names another key than the one verifying it")
	ErrCheckpointSignature = errors.New("an audit checkpoint is not signed by the key it names")
	ErrCheckpointOrder     = errors.New("an audit checkpoint does not follow the checkpoint before it")
)

func KeyID(public ed25519.PublicKey) []byte {
	sum := sha256.Sum256(public)
	return sum[:]
}

// The signed bytes are written beside Checkpoint in the contract, so a verifier
// in any language rebuilds them from the fields it reads.
func SignedBytes(checkpoint *auditv1.Checkpoint) ([]byte, error) {
	for _, field := range []struct {
		name  string
		bytes []byte
	}{{"digest", checkpoint.GetDigest()}, {"previous", checkpoint.GetPrevious()}, {"key", checkpoint.GetKeyId()}} {
		if len(field.bytes) != digestSize {
			return nil, fmt.Errorf("an audit checkpoint's %s holds %d bytes, not %d", field.name, len(field.bytes), digestSize)
		}
	}
	if err := checkpoint.GetSignedAt().CheckValid(); err != nil {
		return nil, fmt.Errorf("an audit checkpoint's signing time: %w", err)
	}
	if len(checkpoint.GetChain()) > math.MaxUint32 {
		return nil, errors.New("an audit checkpoint names a chain too long to sign")
	}
	signed := []byte(checkpointDomain)
	signed = binary.BigEndian.AppendUint32(signed, uint32(len(checkpoint.GetChain())))
	signed = append(signed, checkpoint.GetChain()...)
	signed = binary.BigEndian.AppendUint64(signed, checkpoint.GetSequence())
	signed = binary.BigEndian.AppendUint64(signed, checkpoint.GetPrunedThrough())
	signed = append(signed, checkpoint.GetDigest()...)
	signed = binary.BigEndian.AppendUint64(signed, uint64(checkpoint.GetSignedAt().GetSeconds()))
	signed = binary.BigEndian.AppendUint32(signed, uint32(checkpoint.GetSignedAt().GetNanos()))
	signed = append(signed, checkpoint.GetPrevious()...)
	signed = append(signed, checkpoint.GetKeyId()...)
	return signed, nil
}

func CheckpointDigest(checkpoint *auditv1.Checkpoint) ([]byte, error) {
	signed, err := SignedBytes(checkpoint)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(signed)
	return sum[:], nil
}

// Seal signs where a chain stands. A range is pruned by first sealing its last
// entry, pruned through itself, so the digest the rest of the chain follows is
// kept by a checkpoint nobody without the key can forge.
func Seal(at Chain, prunedThrough uint64, previous []byte, signedAt time.Time, key ed25519.PrivateKey) (*auditv1.Checkpoint, error) {
	if prunedThrough > at.Sequence {
		return nil, fmt.Errorf("an audit checkpoint at %d cannot seal a range pruned through %d", at.Sequence, prunedThrough)
	}
	if len(previous) == 0 {
		previous = make([]byte, digestSize)
	}
	checkpoint := &auditv1.Checkpoint{
		Chain:         at.Name,
		Sequence:      at.Sequence,
		Digest:        at.head(),
		PrunedThrough: prunedThrough,
		SignedAt:      timestamppb.New(signedAt),
		Previous:      previous,
		KeyId:         KeyID(key.Public().(ed25519.PublicKey)),
	}
	signed, err := SignedBytes(checkpoint)
	if err != nil {
		return nil, err
	}
	checkpoint.Signature = ed25519.Sign(key, signed)
	return checkpoint, nil
}

// VerifyCheckpoint holds a checkpoint to the public key and to the digest of the
// checkpoint before it on its chain.
func VerifyCheckpoint(checkpoint *auditv1.Checkpoint, public ed25519.PublicKey, previous []byte) error {
	if len(previous) == 0 {
		previous = make([]byte, digestSize)
	}
	if !bytes.Equal(checkpoint.GetKeyId(), KeyID(public)) {
		return ErrCheckpointKey
	}
	if !bytes.Equal(checkpoint.GetPrevious(), previous) {
		return ErrCheckpointOrder
	}
	signed, err := SignedBytes(checkpoint)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, signed, checkpoint.GetSignature()) {
		return ErrCheckpointSignature
	}
	return nil
}

// From returns the chain as a checkpoint states it, to verify the entries after it.
func From(checkpoint *auditv1.Checkpoint) Chain {
	return Chain{Name: checkpoint.GetChain(), Sequence: checkpoint.GetSequence(), Head: checkpoint.GetDigest()}
}
