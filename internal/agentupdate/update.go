// Package agentupdate states what authorizes an agent update: the root that
// names the keys of both roles and how many of them must agree, the catalog of
// releases agents may install, and what an operator publishes and assigns. It
// reads no store and serves no transport, and it never holds a key that signs:
// the platform verifies what it is given exactly as an agent does and refuses
// whatever a role did not sign.
package agentupdate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const (
	SchemaVersion      = 1
	RootPayloadType    = "application/vnd.seagull.update.v1.root+protobuf"
	CatalogPayloadType = "application/vnd.seagull.update.v1.catalog+protobuf"

	MaxPayloadBytes     = 1 << 20
	MaxEnvelopeBytes    = MaxPayloadBytes + 16<<10
	MaxSignatures       = 16
	MaxKeys             = 16
	MaxRoleKeys         = 8
	MaxReleases         = 256
	MaxReplaced         = 16
	MaxPackageBytes     = 256 << 20
	MaxVersionLength    = 128
	MaxPlatformLength   = 32
	MaxRepositoryLength = 256
	MaxRoots            = 64
	MaxNoteLength       = 512
	MaxVersion          = math.MaxInt64

	MaxLifetime = 366 * 24 * time.Hour
	MaxAhead    = 5 * time.Minute
)

var (
	ErrUnsigned  = errors.New("not enough keys of the role that signs the metadata signed it")
	ErrMalformed = errors.New("the update metadata is not one the platform takes")
	ErrExpired   = errors.New("the update metadata has run out")
	ErrRoot      = errors.New("the update root this platform was given is not usable")
	ErrStale     = errors.New("the platform already holds update metadata at least as new")
)

func KeyID(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func Digest(served []byte) string {
	sum := sha256.Sum256(served)
	return hex.EncodeToString(sum[:])
}

// The signatures are checked over the payload exactly as it arrived and before
// any of it is decoded, and a key counts once however many signatures it made,
// so a threshold is reached only by as many distinct keys of the role.
func signedBy(keys map[string]*ecdsa.PublicKey, role *updatev1.Role, payloadType string, envelope *updatev1.Envelope) ([]string, error) {
	payload, signatures := envelope.GetPayload(), envelope.GetSignatures()
	switch {
	case envelope.GetPayloadType() != payloadType:
		return nil, fmt.Errorf("%w: its payload is declared as %s, and %s was expected",
			ErrMalformed, strconv.Quote(bounded(envelope.GetPayloadType())), payloadType)
	case len(payload) == 0:
		return nil, fmt.Errorf("%w: it carries no payload", ErrMalformed)
	case len(payload) > MaxPayloadBytes:
		return nil, fmt.Errorf("%w: its payload is longer than %d bytes", ErrMalformed, MaxPayloadBytes)
	case len(signatures) == 0:
		return nil, fmt.Errorf("%w: it carries no signature", ErrUnsigned)
	case len(signatures) > MaxSignatures:
		return nil, fmt.Errorf("%w: it carries %d signatures, and metadata carries at most %d",
			ErrMalformed, len(signatures), MaxSignatures)
	}

	digest := sha256.Sum256(agentpolicy.PAE(payloadType, payload))
	var signed []string
	for _, signature := range signatures {
		for _, id := range role.GetKeyids() {
			key := keys[id]
			if key != nil && !slices.Contains(signed, id) && ecdsa.VerifyASN1(key, digest[:], signature.GetSig()) {
				signed = append(signed, id)
			}
		}
	}
	if uint32(len(signed)) < role.GetThreshold() {
		return nil, fmt.Errorf("%w: %d of its keys signed, and %d must", ErrUnsigned, len(signed), role.GetThreshold())
	}
	slices.Sort(signed)
	return signed, nil
}

func Sign(message proto.Message, payloadType string, keys ...crypto.Signer) (*updatev1.Envelope, error) {
	if len(keys) == 0 || len(keys) > MaxSignatures {
		return nil, fmt.Errorf("metadata is signed by between 1 and %d keys", MaxSignatures)
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encode the metadata: %w", err)
	}
	digest := sha256.Sum256(agentpolicy.PAE(payloadType, payload))
	signed := &updatev1.Envelope{Payload: payload, PayloadType: payloadType}
	for _, key := range keys {
		public, ecdsaKey := key.Public().(*ecdsa.PublicKey)
		if !ecdsaKey || public.Curve != elliptic.P256() {
			return nil, errors.New("metadata is signed with ECDSA over P-256")
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, fmt.Errorf("encode a signing key: %w", err)
		}
		signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("sign with key %s: %w", KeyID(der), err)
		}
		signed.Signatures = append(signed.Signatures, &updatev1.Signature{Sig: signature, Keyid: KeyID(der)})
	}
	return signed, nil
}

func Encode(envelope *updatev1.Envelope) ([]byte, error) {
	served, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: the envelope cannot be encoded again", ErrMalformed)
	}
	if len(served) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: the envelope is longer than %d bytes", ErrMalformed, MaxEnvelopeBytes)
	}
	return served, nil
}

func decode(served []byte) (*updatev1.Envelope, error) {
	if len(served) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: the envelope is longer than %d bytes", ErrMalformed, MaxEnvelopeBytes)
	}
	var envelope updatev1.Envelope
	if err := proto.Unmarshal(served, &envelope); err != nil {
		return nil, fmt.Errorf("%w: it is not an envelope", ErrMalformed)
	}
	return &envelope, nil
}

func known(message protoreflect.Message) error {
	if len(message.GetUnknown()) > 0 {
		return fmt.Errorf("%w: its %s holds fields this platform does not know", ErrMalformed, message.Descriptor().Name())
	}
	var found error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.Message() == nil:
		case field.IsList():
			for index := range value.List().Len() {
				if found = known(value.List().Get(index).Message()); found != nil {
					return false
				}
			}
		default:
			found = known(value.Message())
		}
		return found == nil
	})
	return found
}

func bounded(value string) string {
	if len(value) > 96 {
		return value[:96]
	}
	return value
}
