package agentupdate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// A root the platform trusts, with the keys it names decoded and the envelope
// it is served as.
type Root struct {
	root     *updatev1.Root
	served   []byte
	keys     map[string]*ecdsa.PublicKey
	signedBy []string
}

func (r *Root) Version() uint64 { return r.root.GetVersion() }

func (r *Root) IssuedAt() time.Time { return r.root.GetIssuedAt().AsTime() }

func (r *Root) ExpiresAt() time.Time { return r.root.GetExpiresAt().AsTime() }

func (r *Root) Expired(at time.Time) bool { return !at.Before(r.ExpiresAt()) }

func (r *Root) Served() []byte { return r.served }

func (r *Root) SignedBy() []string { return slices.Clone(r.signedBy) }

func (r *Root) Message() *updatev1.Root {
	cloned, _ := proto.Clone(r.root).(*updatev1.Root)
	return cloned
}

// The root this platform was configured with, trusted because of where it came
// from. It is still held to its own root role, so a file that is not a root its
// own keys signed is refused rather than trusted. It may have run out: an
// expired root still leads to the next one in the chain.
func Anchor(served []byte, now time.Time) (*Root, error) {
	envelope, err := decode(served)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoot, err)
	}
	if envelope.GetPayloadType() != RootPayloadType {
		return nil, fmt.Errorf("%w: its payload is declared as %s, and a root is %s",
			ErrRoot, strconv.Quote(bounded(envelope.GetPayloadType())), RootPayloadType)
	}
	root, keys, err := decodeRoot(envelope.GetPayload(), now)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoot, err)
	}
	signed, err := signedBy(keys, root.GetRoot(), RootPayloadType, envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: its own root keys did not sign it: %v", ErrRoot, err)
	}
	encoded, err := Encode(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoot, err)
	}
	return &Root{root: root, served: encoded, keys: keys, signedBy: signed}, nil
}

// The root after this one, which a threshold of this root's root keys and a
// threshold of its own root keys must both have signed. This root's keys are
// checked first, so a payload this root did not vouch for is never decoded.
func (r *Root) Next(envelope *updatev1.Envelope, now time.Time) (*Root, error) {
	before, err := signedBy(r.keys, r.root.GetRoot(), RootPayloadType, envelope)
	if err != nil {
		return nil, fmt.Errorf("the root keys of version %d did not sign it: %w", r.Version(), err)
	}
	root, keys, err := decodeRoot(envelope.GetPayload(), now)
	if err != nil {
		return nil, err
	}
	switch {
	case root.GetVersion() <= r.Version():
		return nil, fmt.Errorf("%w: it is root %d, and root %d is already held", ErrStale, root.GetVersion(), r.Version())
	case root.GetVersion() != r.Version()+1:
		return nil, fmt.Errorf("%w: it is root %d, and the root after version %d is version %d",
			ErrMalformed, root.GetVersion(), r.Version(), r.Version()+1)
	}
	after, err := signedBy(keys, root.GetRoot(), RootPayloadType, envelope)
	if err != nil {
		return nil, fmt.Errorf("its own root keys did not sign it: %w", err)
	}
	encoded, err := Encode(envelope)
	if err != nil {
		return nil, err
	}
	signed := slices.Compact(slices.Sorted(slices.Values(append(before, after...))))
	return &Root{root: root, served: encoded, keys: keys, signedBy: signed}, nil
}

// The newest root reached from this one through the roots after it, oldest
// first and each the next version of the one before.
func (r *Root) Walk(served [][]byte, now time.Time) (*Root, error) {
	current := r
	for _, encoded := range served {
		envelope, err := decode(encoded)
		if err != nil {
			return nil, fmt.Errorf("root %d: %w", current.Version()+1, err)
		}
		next, err := current.Next(envelope, now)
		if err != nil {
			return nil, fmt.Errorf("root %d: %w", current.Version()+1, err)
		}
		current = next
	}
	return current, nil
}

func decodeRoot(payload []byte, now time.Time) (*updatev1.Root, map[string]*ecdsa.PublicKey, error) {
	var root updatev1.Root
	if err := proto.Unmarshal(payload, &root); err != nil {
		return nil, nil, fmt.Errorf("%w: its payload is not a root", ErrMalformed)
	}
	if err := known(root.ProtoReflect()); err != nil {
		return nil, nil, err
	}
	switch {
	case root.GetSchemaVersion() != SchemaVersion:
		return nil, nil, fmt.Errorf("%w: the root is written to schema %d, and this platform reads %d",
			ErrMalformed, root.GetSchemaVersion(), SchemaVersion)
	case root.GetVersion() == 0 || root.GetVersion() > MaxVersion:
		return nil, nil, fmt.Errorf("%w: a root is counted from version 1 to %d", ErrMalformed, uint64(MaxVersion))
	}
	if err := lifetime("the root", root.GetIssuedAt(), root.GetExpiresAt(), now); err != nil {
		return nil, nil, err
	}
	keys, err := publicKeys(root.GetKeys())
	if err != nil {
		return nil, nil, err
	}
	if err := role("root", root.GetRoot(), keys); err != nil {
		return nil, nil, err
	}
	if err := role("catalog", root.GetCatalog(), keys); err != nil {
		return nil, nil, err
	}
	return &root, keys, nil
}

func publicKeys(named []*updatev1.Key) (map[string]*ecdsa.PublicKey, error) {
	if len(named) == 0 || len(named) > MaxKeys {
		return nil, fmt.Errorf("%w: a root names between 1 and %d keys, and this one names %d", ErrMalformed, MaxKeys, len(named))
	}
	keys := make(map[string]*ecdsa.PublicKey, len(named))
	for _, key := range named {
		id := key.GetKeyid()
		if id != KeyID(key.GetPublicKey()) {
			return nil, fmt.Errorf("%w: key %s is not the SHA-256 of the key it names", ErrMalformed, strconv.Quote(bounded(id)))
		}
		if _, listed := keys[id]; listed {
			return nil, fmt.Errorf("%w: key %s is named twice", ErrMalformed, id)
		}
		parsed, err := x509.ParsePKIXPublicKey(key.GetPublicKey())
		if err != nil {
			return nil, fmt.Errorf("%w: key %s does not parse", ErrMalformed, id)
		}
		public, ecdsaKey := parsed.(*ecdsa.PublicKey)
		if !ecdsaKey || public.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: key %s is not ECDSA over P-256", ErrMalformed, id)
		}
		keys[id] = public
	}
	return keys, nil
}

func role(name string, held *updatev1.Role, keys map[string]*ecdsa.PublicKey) error {
	ids := held.GetKeyids()
	switch {
	case held == nil:
		return fmt.Errorf("%w: the root names no %s role", ErrMalformed, name)
	case len(ids) == 0 || len(ids) > MaxRoleKeys:
		return fmt.Errorf("%w: the %s role names between 1 and %d keys, and this one names %d", ErrMalformed, name, MaxRoleKeys, len(ids))
	case held.GetThreshold() == 0 || held.GetThreshold() > uint32(len(ids)):
		return fmt.Errorf("%w: the %s role needs between 1 and %d signatures, and asks for %d",
			ErrMalformed, name, len(ids), held.GetThreshold())
	}
	for index, id := range ids {
		if _, found := keys[id]; !found {
			return fmt.Errorf("%w: the %s role names key %s, which the root does not hold", ErrMalformed, name, strconv.Quote(bounded(id)))
		}
		if slices.Contains(ids[:index], id) {
			return fmt.Errorf("%w: the %s role names key %s twice", ErrMalformed, name, id)
		}
	}
	return nil
}

func lifetime(what string, issued, expires *timestamppb.Timestamp, now time.Time) error {
	switch {
	case issued == nil || !issued.IsValid():
		return fmt.Errorf("%w: %s does not say when it was issued", ErrMalformed, what)
	case expires == nil || !expires.IsValid():
		return fmt.Errorf("%w: %s does not say when it runs out", ErrMalformed, what)
	case issued.AsTime().After(now.Add(MaxAhead)):
		return fmt.Errorf("%w: %s was issued more than %s ahead of this platform's clock", ErrMalformed, what, MaxAhead)
	case !expires.AsTime().After(issued.AsTime()):
		return fmt.Errorf("%w: %s runs out before it was issued", ErrMalformed, what)
	case expires.AsTime().Sub(issued.AsTime()) > MaxLifetime:
		return fmt.Errorf("%w: %s is vouched for longer than %s", ErrMalformed, what, MaxLifetime)
	}
	return nil
}
