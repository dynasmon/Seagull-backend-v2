package agentpolicy_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

var written = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func signingKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a signing key: %v", err)
	}
	return key
}

func publicPEM(t *testing.T, keys ...crypto.PublicKey) []byte {
	t.Helper()
	var encoded []byte
	for _, key := range keys {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatalf("encode a public key: %v", err)
		}
		encoded = append(encoded, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...)
	}
	return encoded
}

func signers(t *testing.T, keys ...*ecdsa.PrivateKey) *agentpolicy.Signers {
	t.Helper()
	public := make([]crypto.PublicKey, 0, len(keys))
	for _, key := range keys {
		public = append(public, &key.PublicKey)
	}
	held, err := agentpolicy.ParseSigners(publicPEM(t, public...))
	if err != nil {
		t.Fatalf("read the signers: %v", err)
	}
	return held
}

func keyID(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	id, err := agentpolicy.KeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("name a key: %v", err)
	}
	return id
}

func wellFormed() *policyv1.Policy {
	return &policyv1.Policy{
		SchemaVersion: agentpolicy.SchemaVersion,
		PolicyId:      "linux-web",
		Revision:      7,
		Targets:       &policyv1.Targets{AgentIds: []string{"web-01", "web-02"}},
		IssuedAt:      timestamppb.New(written),
		ExpiresAt:     timestamppb.New(written.Add(30 * 24 * time.Hour)),
		Settings:      &policyv1.Settings{LogLevel: policyv1.LogLevel_LOG_LEVEL_WARN},
	}
}

func signed(t *testing.T, policy *policyv1.Policy, keys ...*ecdsa.PrivateKey) *policyv1.SignedPolicy {
	t.Helper()
	signing := make([]crypto.Signer, 0, len(keys))
	for _, key := range keys {
		signing = append(signing, key)
	}
	envelope, err := agentpolicy.Sign(policy, signing...)
	if err != nil {
		t.Fatalf("sign the policy: %v", err)
	}
	return envelope
}

func TestPAEIsTheEncodingDSSESigns(t *testing.T) {
	encoded := agentpolicy.PAE("http://example.com/HelloWorld", []byte("hello world"))
	if want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"; string(encoded) != want {
		t.Fatalf("the pre-authentication encoding is %q, and DSSE signs %q", encoded, want)
	}
}

func TestASignedPolicyIsVerifiedUnderAKeyThePlatformAccepts(t *testing.T) {
	key := signingKey(t)
	verified, err := signers(t, key).Verify(signed(t, wellFormed(), key))
	if err != nil {
		t.Fatalf("a policy signed by an accepted key was refused: %v", err)
	}
	if !proto.Equal(verified.Policy, wellFormed()) {
		t.Fatalf("verifying read %v out of what was signed", verified.Policy)
	}
	if !slices.Equal(verified.SignedBy, []string{keyID(t, key)}) {
		t.Fatalf("the policy is said to be signed by %v", verified.SignedBy)
	}
}

func TestTheSignatureCoversThePayloadTypeAndEveryByteOfThePayload(t *testing.T) {
	key := signingKey(t)
	accepted := signers(t, key)

	changed := signed(t, wellFormed(), key)
	changed.Payload[len(changed.Payload)-1] ^= 0x01
	if _, err := accepted.Verify(changed); !errors.Is(err, agentpolicy.ErrUnsigned) {
		t.Fatalf("a payload changed after signing was answered %v", err)
	}

	retyped := signed(t, wellFormed(), key)
	payload := retyped.GetPayload()
	digest := sha256.Sum256(agentpolicy.PAE("application/vnd.seagull.release.v1+protobuf", payload))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign under another payload type: %v", err)
	}
	retyped.Signatures = []*policyv1.Signature{{Sig: signature}}
	if _, err := accepted.Verify(retyped); !errors.Is(err, agentpolicy.ErrUnsigned) {
		t.Fatalf("a signature made over another payload type was answered %v", err)
	}

	declared := signed(t, wellFormed(), key)
	declared.PayloadType = "application/json"
	if _, err := accepted.Verify(declared); !errors.Is(err, agentpolicy.ErrMalformed) {
		t.Fatalf("an envelope declaring another payload type was answered %v", err)
	}
}

func TestAPolicyNoAcceptedKeySignedIsRefused(t *testing.T) {
	key, stranger := signingKey(t), signingKey(t)

	if _, err := signers(t, key).Verify(signed(t, wellFormed(), stranger)); !errors.Is(err, agentpolicy.ErrUnsigned) {
		t.Fatalf("a policy signed by a key the platform was not given was answered %v", err)
	}
	unsigned := signed(t, wellFormed(), key)
	unsigned.Signatures = nil
	if _, err := signers(t, key).Verify(unsigned); !errors.Is(err, agentpolicy.ErrUnsigned) {
		t.Fatalf("a policy carrying no signature was answered %v", err)
	}
	claimed := signed(t, wellFormed(), stranger)
	claimed.Signatures[0].Keyid = keyID(t, key)
	if _, err := signers(t, key).Verify(claimed); !errors.Is(err, agentpolicy.ErrUnsigned) {
		t.Fatalf("a signature claiming an accepted key's id was answered %v", err)
	}
}

func TestOneAcceptedSignatureIsEnoughWhileAKeyIsRotated(t *testing.T) {
	previous, next := signingKey(t), signingKey(t)
	envelope := signed(t, wellFormed(), previous, next)

	for name, accepted := range map[string][]*ecdsa.PrivateKey{
		"holding the previous key": {previous},
		"holding the next key":     {next},
		"holding both":             {next, previous},
	} {
		t.Run(name, func(t *testing.T) {
			verified, err := signers(t, accepted...).Verify(envelope)
			if err != nil {
				t.Fatalf("the policy was refused: %v", err)
			}
			var want []string
			for _, key := range accepted {
				want = append(want, keyID(t, key))
			}
			slices.Sort(want)
			if !slices.Equal(verified.SignedBy, want) {
				t.Fatalf("the policy is said to be signed by %v, and %v signed it", verified.SignedBy, want)
			}
		})
	}
}

func TestAnEnvelopeOutsideItsBoundsIsRefusedBeforeItIsRead(t *testing.T) {
	key := signingKey(t)
	accepted := signers(t, key)

	crowded := signed(t, wellFormed(), key)
	for range agentpolicy.MaxSignatures {
		crowded.Signatures = append(crowded.Signatures, crowded.Signatures[0])
	}
	if _, err := accepted.Verify(crowded); !errors.Is(err, agentpolicy.ErrMalformed) {
		t.Fatalf("an envelope carrying %d signatures was answered %v", len(crowded.Signatures), err)
	}

	large := signed(t, wellFormed(), key)
	large.Payload = make([]byte, agentpolicy.MaxPayloadBytes+1)
	if _, err := accepted.Verify(large); !errors.Is(err, agentpolicy.ErrMalformed) {
		t.Fatalf("a payload over the ceiling was answered %v", err)
	}

	empty := signed(t, wellFormed(), key)
	empty.Payload = nil
	if _, err := accepted.Verify(empty); !errors.Is(err, agentpolicy.ErrMalformed) {
		t.Fatalf("an envelope carrying no payload was answered %v", err)
	}
}

func TestAPolicyHoldingFieldsThePlatformDoesNotKnowIsRefused(t *testing.T) {
	key := signingKey(t)
	payload, err := proto.Marshal(wellFormed())
	if err != nil {
		t.Fatalf("encode the policy: %v", err)
	}
	payload = protowire.AppendTag(payload, 99, protowire.VarintType)
	payload = protowire.AppendVarint(payload, 1)

	digest := sha256.Sum256(agentpolicy.PAE(agentpolicy.PayloadType, payload))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	envelope := &policyv1.SignedPolicy{
		Payload:     payload,
		PayloadType: agentpolicy.PayloadType,
		Signatures:  []*policyv1.Signature{{Sig: signature}},
	}
	if _, err := signers(t, key).Verify(envelope); !errors.Is(err, agentpolicy.ErrMalformed) {
		t.Fatalf("a signed policy holding an unknown field was answered %v", err)
	}
}

func TestSignersArePublicKeysOverP256AndNothingElse(t *testing.T) {
	key := signingKey(t)
	wider, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a P-384 key: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate an RSA key: %v", err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encode a private key: %v", err)
	}

	for name, content := range map[string][]byte{
		"nothing":         nil,
		"a P-384 key":     publicPEM(t, &wider.PublicKey),
		"an RSA key":      publicPEM(t, &other.PublicKey),
		"a private key":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
		"text":            []byte("not a key"),
		"one key twice":   publicPEM(t, &key.PublicKey, &key.PublicKey),
		"a broken block":  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x30, 0x01}}),
		"a key then text": append(publicPEM(t, &key.PublicKey), []byte("trailing")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := agentpolicy.ParseSigners(content); !errors.Is(err, agentpolicy.ErrSigners) {
				t.Fatalf("signers holding %s were answered %v", name, err)
			}
		})
	}

	held, err := agentpolicy.ParseSigners(publicPEM(t, &key.PublicKey))
	if err != nil || held.Count() != 1 {
		t.Fatalf("one P-256 key was read as %v, %v", held, err)
	}
}
