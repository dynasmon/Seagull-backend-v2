package agentupdate_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

var written = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

type signer struct {
	key *ecdsa.PrivateKey
	id  string
	der []byte
}

func newSigner(t *testing.T) signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a signing key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode a public key: %v", err)
	}
	return signer{key: key, id: agentupdate.KeyID(der), der: der}
}

func rootOf(version uint64, rootKeys []signer, rootThreshold uint32, catalogKeys []signer, catalogThreshold uint32) *updatev1.Root {
	root := &updatev1.Root{
		SchemaVersion: agentupdate.SchemaVersion,
		Version:       version,
		IssuedAt:      timestamppb.New(written),
		ExpiresAt:     timestamppb.New(written.Add(180 * 24 * time.Hour)),
		Root:          &updatev1.Role{Threshold: rootThreshold},
		Catalog:       &updatev1.Role{Threshold: catalogThreshold},
	}
	held := map[string]bool{}
	for _, key := range append(append([]signer{}, rootKeys...), catalogKeys...) {
		if !held[key.id] {
			held[key.id] = true
			root.Keys = append(root.Keys, &updatev1.Key{Keyid: key.id, PublicKey: key.der})
		}
	}
	for _, key := range rootKeys {
		root.Root.Keyids = append(root.Root.Keyids, key.id)
	}
	for _, key := range catalogKeys {
		root.Catalog.Keyids = append(root.Catalog.Keyids, key.id)
	}
	return root
}

func sign(t *testing.T, message proto.Message, payloadType string, keys ...signer) *updatev1.Envelope {
	t.Helper()
	signers := make([]crypto.Signer, 0, len(keys))
	for _, key := range keys {
		signers = append(signers, key.key)
	}
	envelope, err := agentupdate.Sign(message, payloadType, signers...)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return envelope
}

func encoded(t *testing.T, envelope *updatev1.Envelope) []byte {
	t.Helper()
	served, err := agentupdate.Encode(envelope)
	if err != nil {
		t.Fatalf("encode an envelope: %v", err)
	}
	return served
}

func anchored(t *testing.T, root *updatev1.Root, keys ...signer) *agentupdate.Root {
	t.Helper()
	trusted, err := agentupdate.Anchor(encoded(t, sign(t, root, agentupdate.RootPayloadType, keys...)), written)
	if err != nil {
		t.Fatalf("anchor root %d: %v", root.GetVersion(), err)
	}
	return trusted
}

func TestThePlatformTrustsTheRootItWasGivenOnlyWhenItsOwnRootKeysSignedIt(t *testing.T) {
	owner, stranger := newSigner(t), newSigner(t)
	root := rootOf(1, []signer{owner}, 1, []signer{owner}, 1)

	trusted := anchored(t, root, owner)
	if trusted.Version() != 1 || len(trusted.SignedBy()) != 1 || trusted.SignedBy()[0] != owner.id {
		t.Fatalf("anchored root %d signed by %v", trusted.Version(), trusted.SignedBy())
	}
	if _, err := agentupdate.Anchor(encoded(t, sign(t, root, agentupdate.RootPayloadType, stranger)), written); !errors.Is(err, agentupdate.ErrRoot) {
		t.Fatalf("a root its own keys did not sign was trusted: %v", err)
	}
	if _, err := agentupdate.Anchor(encoded(t, sign(t, root, agentupdate.CatalogPayloadType, owner)), written); !errors.Is(err, agentupdate.ErrRoot) {
		t.Fatalf("a root signed as a catalog was trusted: %v", err)
	}
	if _, err := agentupdate.Anchor([]byte("not an envelope"), written); !errors.Is(err, agentupdate.ErrRoot) {
		t.Fatalf("bytes that are no envelope were trusted: %v", err)
	}
}

func TestARootMustStateItsKeysAndRolesWithinTheirBounds(t *testing.T) {
	owner, other := newSigner(t), newSigner(t)
	wide, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wideDER, err := x509.MarshalPKIXPublicKey(&wide.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	for name, change := range map[string]func(*updatev1.Root){
		"another schema":                 func(r *updatev1.Root) { r.SchemaVersion = 2 },
		"version zero":                   func(r *updatev1.Root) { r.Version = 0 },
		"no issue time":                  func(r *updatev1.Root) { r.IssuedAt = nil },
		"no expiry":                      func(r *updatev1.Root) { r.ExpiresAt = nil },
		"issued ahead of the clock":      func(r *updatev1.Root) { r.IssuedAt = timestamppb.New(written.Add(6 * time.Minute)) },
		"running out before its issue":   func(r *updatev1.Root) { r.ExpiresAt = timestamppb.New(written.Add(-time.Second)) },
		"vouched for more than 366 days": func(r *updatev1.Root) { r.ExpiresAt = timestamppb.New(written.Add(367 * 24 * time.Hour)) },
		"no key":                         func(r *updatev1.Root) { r.Keys = nil },
		"a key id that is not its hash":  func(r *updatev1.Root) { r.Keys[0].Keyid = other.id },
		"a key named twice":              func(r *updatev1.Root) { r.Keys = append(r.Keys, r.Keys[0]) },
		"a key off P-256": func(r *updatev1.Root) {
			r.Keys = append(r.Keys, &updatev1.Key{Keyid: agentupdate.KeyID(wideDER), PublicKey: wideDER})
		},
		"a key that does not parse": func(r *updatev1.Root) {
			r.Keys = append(r.Keys, &updatev1.Key{Keyid: agentupdate.KeyID([]byte("junk")), PublicKey: []byte("junk")})
		},
		"no root role":                 func(r *updatev1.Root) { r.Root = nil },
		"no catalog role":              func(r *updatev1.Root) { r.Catalog = nil },
		"a role naming a key it lacks": func(r *updatev1.Root) { r.Catalog.Keyids = []string{other.id} },
		"a role naming a key twice":    func(r *updatev1.Root) { r.Catalog.Keyids = []string{owner.id, owner.id} },
		"a threshold of zero":          func(r *updatev1.Root) { r.Catalog.Threshold = 0 },
		"a threshold beyond its keys":  func(r *updatev1.Root) { r.Catalog.Threshold = 2 },
		"more keys than a root may name": func(r *updatev1.Root) {
			for range agentupdate.MaxKeys {
				extra := newSigner(t)
				r.Keys = append(r.Keys, &updatev1.Key{Keyid: extra.id, PublicKey: extra.der})
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := rootOf(1, []signer{owner}, 1, []signer{owner}, 1)
			change(root)
			if _, err := agentupdate.Anchor(encoded(t, sign(t, root, agentupdate.RootPayloadType, owner)), written); !errors.Is(err, agentupdate.ErrRoot) {
				t.Fatalf("taken: %v", err)
			}
		})
	}
}

func TestARootCarryingAFieldThisPlatformDoesNotKnowIsRefused(t *testing.T) {
	owner := newSigner(t)
	payload, err := proto.Marshal(rootOf(1, []signer{owner}, 1, []signer{owner}, 1))
	if err != nil {
		t.Fatal(err)
	}
	payload = protowire.AppendVarint(protowire.AppendTag(payload, 99, protowire.VarintType), 1)
	var withUnknown updatev1.Root
	if err := proto.Unmarshal(payload, &withUnknown); err != nil {
		t.Fatal(err)
	}
	if _, err := agentupdate.Anchor(encoded(t, sign(t, &withUnknown, agentupdate.RootPayloadType, owner)), written); !errors.Is(err, agentupdate.ErrRoot) {
		t.Fatalf("a root with an unknown field was trusted: %v", err)
	}
}

func TestTheNextRootIsTrustedOnlyWhenTheThresholdsOfBothRootsSignedIt(t *testing.T) {
	before, after := newSigner(t), newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{before}, 1, []signer{before}, 1), before)
	next := rootOf(2, []signer{after}, 1, []signer{after}, 1)

	rotated, err := trusted.Next(sign(t, next, agentupdate.RootPayloadType, before, after), written)
	if err != nil {
		t.Fatalf("a rotation both roots signed was refused: %v", err)
	}
	if rotated.Version() != 2 || len(rotated.SignedBy()) != 2 {
		t.Fatalf("rotated to root %d signed by %v", rotated.Version(), rotated.SignedBy())
	}
	if _, err := trusted.Next(sign(t, next, agentupdate.RootPayloadType, before), written); !errors.Is(err, agentupdate.ErrUnsigned) {
		t.Fatalf("a root its own keys did not sign was trusted: %v", err)
	}
	if _, err := trusted.Next(sign(t, next, agentupdate.RootPayloadType, after), written); !errors.Is(err, agentupdate.ErrUnsigned) {
		t.Fatalf("a root the previous one did not vouch for was trusted: %v", err)
	}
}

func TestAThresholdIsReachedOnlyByAsManyDistinctKeys(t *testing.T) {
	first, second := newSigner(t), newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{first, second}, 2, []signer{first}, 1), first, second)
	next := rootOf(2, []signer{first, second}, 2, []signer{first}, 1)

	twice := sign(t, next, agentupdate.RootPayloadType, first)
	twice.Signatures = append(twice.Signatures, sign(t, next, agentupdate.RootPayloadType, first).GetSignatures()...)
	if _, err := trusted.Next(twice, written); !errors.Is(err, agentupdate.ErrUnsigned) {
		t.Fatalf("one key signing twice reached a threshold of two: %v", err)
	}
	if _, err := trusted.Next(sign(t, next, agentupdate.RootPayloadType, first, second), written); err != nil {
		t.Fatalf("two keys of a threshold of two were refused: %v", err)
	}
}

func TestARootIsNeverSkippedNorTakenTwice(t *testing.T) {
	owner := newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)

	if _, err := trusted.Next(sign(t, rootOf(3, []signer{owner}, 1, []signer{owner}, 1), agentupdate.RootPayloadType, owner), written); !errors.Is(err, agentupdate.ErrMalformed) {
		t.Fatalf("a root that skips a version was trusted: %v", err)
	}
	if _, err := trusted.Next(sign(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), agentupdate.RootPayloadType, owner), written); !errors.Is(err, agentupdate.ErrStale) {
		t.Fatalf("the root already held was taken again: %v", err)
	}
}

func TestAWalkFollowsTheChainAndStopsAtAGap(t *testing.T) {
	first, second, third := newSigner(t), newSigner(t), newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{first}, 1, []signer{first}, 1), first)
	two := encoded(t, sign(t, rootOf(2, []signer{second}, 1, []signer{second}, 1), agentupdate.RootPayloadType, first, second))
	three := encoded(t, sign(t, rootOf(3, []signer{third}, 1, []signer{third}, 1), agentupdate.RootPayloadType, second, third))

	newest, err := trusted.Walk([][]byte{two, three}, written)
	if err != nil || newest.Version() != 3 {
		t.Fatalf("walked to %v: %v", newest, err)
	}
	if _, err := trusted.Walk([][]byte{three}, written); err == nil {
		t.Fatal("a chain with a gap was walked")
	}
}

func TestARootThatRanOutStillLeadsToTheNext(t *testing.T) {
	old, current := newSigner(t), newSigner(t)
	expired := rootOf(1, []signer{old}, 1, []signer{old}, 1)
	expired.IssuedAt = timestamppb.New(written.Add(-400 * 24 * time.Hour))
	expired.ExpiresAt = timestamppb.New(written.Add(-40 * 24 * time.Hour))
	trusted := anchored(t, expired, old)
	if !trusted.Expired(written) {
		t.Fatal("a root that ran out reads as in force")
	}

	next, err := trusted.Next(sign(t, rootOf(2, []signer{current}, 1, []signer{current}, 1), agentupdate.RootPayloadType, old, current), written)
	if err != nil {
		t.Fatalf("a root that ran out did not lead to the next: %v", err)
	}
	if next.Expired(written) {
		t.Fatal("the next root reads as run out")
	}
}
