// Package agentpolicy states what a signed agent policy is: the envelope it
// travels in, the keys a signature is accepted under and what a policy may set.
// It reads no store and serves no transport, and it never holds a key that
// signs: the platform is given public keys and refuses whatever none of them
// signed.
package agentpolicy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const (
	SchemaVersion    = 1
	PayloadType      = "application/vnd.seagull.policy.v1+protobuf"
	MaxPayloadBytes  = 1 << 20
	MaxEnvelopeBytes = MaxPayloadBytes + 4<<10
	MaxSignatures    = 4
	MaxSigners       = 64
	MaxSignersBytes  = 64 << 10
)

var (
	ErrUnsigned  = errors.New("no signature on the policy was made by a key the platform accepts")
	ErrMalformed = errors.New("the policy is not one the platform takes")
	ErrSigners   = errors.New("the policy signers are not usable")
)

type Signers struct {
	keys []signer
}

type signer struct {
	id  string
	key *ecdsa.PublicKey
}

// The public keys a policy is accepted under, as PEM blocks of DER
// SubjectPublicKeyInfo. Only P-256 is taken, because that is the one curve the
// contract signs with, and a file holding anything else is refused whole
// rather than read in part.
func ParseSigners(content []byte) (*Signers, error) {
	if len(content) > MaxSignersBytes {
		return nil, fmt.Errorf("%w: they are longer than %d bytes", ErrSigners, MaxSignersBytes)
	}
	held := &Signers{}
	for rest := content; len(bytes.TrimSpace(rest)) > 0; {
		block, remainder := pem.Decode(rest)
		switch {
		case block == nil:
			return nil, fmt.Errorf("%w: they hold something that is not PEM", ErrSigners)
		case block.Type != "PUBLIC KEY":
			return nil, fmt.Errorf("%w: they hold a %s block, and a signer is a PUBLIC KEY", ErrSigners, strconv.Quote(block.Type))
		case len(held.keys) == MaxSigners:
			return nil, fmt.Errorf("%w: they hold more than %d keys", ErrSigners, MaxSigners)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: a key does not parse: %v", ErrSigners, err)
		}
		key, ecdsaKey := parsed.(*ecdsa.PublicKey)
		if !ecdsaKey || key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: a key is not ECDSA over P-256", ErrSigners)
		}
		id, err := KeyID(key)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(held.keys, func(known signer) bool { return known.id == id }) {
			return nil, fmt.Errorf("%w: key %s is listed twice", ErrSigners, id)
		}
		held.keys = append(held.keys, signer{id: id, key: key})
		rest = remainder
	}
	if len(held.keys) == 0 {
		return nil, fmt.Errorf("%w: they hold no key", ErrSigners)
	}
	return held, nil
}

func (s *Signers) Count() int { return len(s.keys) }

func KeyID(key crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("%w: a key cannot be encoded: %v", ErrSigners, err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// DSSE's pre-authentication encoding. The payload type is part of what is
// signed, so a signature over a policy cannot stand for anything else the same
// key signs.
func PAE(payloadType string, payload []byte) []byte {
	encoded := make([]byte, 0, len(payloadType)+len(payload)+32)
	encoded = append(encoded, "DSSEv1 "...)
	encoded = strconv.AppendInt(encoded, int64(len(payloadType)), 10)
	encoded = append(encoded, ' ')
	encoded = append(encoded, payloadType...)
	encoded = append(encoded, ' ')
	encoded = strconv.AppendInt(encoded, int64(len(payload)), 10)
	encoded = append(encoded, ' ')
	return append(encoded, payload...)
}

type Verified struct {
	Policy   *policyv1.Policy
	SignedBy []string
}

// The signature is checked over the payload exactly as it arrived and before
// any of it is decoded, so a payload nobody signed is never parsed.
func (s *Signers) Verify(envelope *policyv1.SignedPolicy) (Verified, error) {
	payload, signatures := envelope.GetPayload(), envelope.GetSignatures()
	switch {
	case envelope.GetPayloadType() != PayloadType:
		return Verified{}, fmt.Errorf("%w: its payload is declared as %s, and a policy is %s",
			ErrMalformed, strconv.Quote(bounded(envelope.GetPayloadType())), PayloadType)
	case len(payload) == 0:
		return Verified{}, fmt.Errorf("%w: it carries no payload", ErrMalformed)
	case len(payload) > MaxPayloadBytes:
		return Verified{}, fmt.Errorf("%w: its payload is longer than %d bytes", ErrMalformed, MaxPayloadBytes)
	case len(signatures) == 0:
		return Verified{}, ErrUnsigned
	case len(signatures) > MaxSignatures:
		return Verified{}, fmt.Errorf("%w: it carries %d signatures, and a policy carries at most %d",
			ErrMalformed, len(signatures), MaxSignatures)
	}

	digest := sha256.Sum256(PAE(PayloadType, payload))
	var signedBy []string
	for _, signature := range signatures {
		for _, candidate := range s.keys {
			if !slices.Contains(signedBy, candidate.id) && ecdsa.VerifyASN1(candidate.key, digest[:], signature.GetSig()) {
				signedBy = append(signedBy, candidate.id)
			}
		}
	}
	if len(signedBy) == 0 {
		return Verified{}, ErrUnsigned
	}
	slices.Sort(signedBy)

	var policy policyv1.Policy
	if err := proto.Unmarshal(payload, &policy); err != nil {
		return Verified{}, fmt.Errorf("%w: its payload is not a policy", ErrMalformed)
	}
	if err := known(policy.ProtoReflect()); err != nil {
		return Verified{}, err
	}
	return Verified{Policy: &policy, SignedBy: signedBy}, nil
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

func Sign(policy *policyv1.Policy, keys ...crypto.Signer) (*policyv1.SignedPolicy, error) {
	if len(keys) == 0 || len(keys) > MaxSignatures {
		return nil, fmt.Errorf("a policy is signed by between 1 and %d keys", MaxSignatures)
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("encode the policy: %w", err)
	}
	digest := sha256.Sum256(PAE(PayloadType, payload))
	signed := &policyv1.SignedPolicy{Payload: payload, PayloadType: PayloadType}
	for _, key := range keys {
		public, ecdsaKey := key.Public().(*ecdsa.PublicKey)
		if !ecdsaKey || public.Curve != elliptic.P256() {
			return nil, errors.New("a policy is signed with ECDSA over P-256")
		}
		id, err := KeyID(public)
		if err != nil {
			return nil, err
		}
		signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("sign the policy with key %s: %w", id, err)
		}
		signed.Signatures = append(signed.Signatures, &policyv1.Signature{Sig: signature, Keyid: id})
	}
	return signed, nil
}

func Digest(served []byte) string {
	sum := sha256.Sum256(served)
	return hex.EncodeToString(sum[:])
}

func bounded(value string) string {
	if len(value) > 96 {
		return value[:96]
	}
	return value
}
