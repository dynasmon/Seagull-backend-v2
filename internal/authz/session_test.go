package authz_test

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
)

func issuer(t *testing.T, lifetime time.Duration) *authz.Issuer {
	t.Helper()
	key, err := authz.RandomSessionKey()
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	made, err := authz.NewIssuer(key, lifetime)
	if err != nil {
		t.Fatalf("build an issuer: %v", err)
	}
	return made
}

func fingerprint(of string) [sha256.Size]byte { return sha256.Sum256([]byte(of)) }

var when = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

func TestASessionComesBackSayingWhatItSaid(t *testing.T) {
	minted := issuer(t, 15*time.Minute)
	binding := fingerprint("alice's certificate")

	session, token, err := minted.Issue("alice", binding, when)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if session.Empty() || session.ID() == "" {
		t.Fatal("the session has no identity")
	}
	if session.ExpiresAt().Sub(session.IssuedAt()) != 15*time.Minute {
		t.Errorf("the session lasts %v", session.ExpiresAt().Sub(session.IssuedAt()))
	}

	read, err := minted.Verify(token, binding, when.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if read.ID() != session.ID() || read.Subject() != "alice" {
		t.Errorf("the token came back as %q for %q", read.ID(), read.Subject())
	}
	if !read.ExpiresAt().Equal(session.ExpiresAt()) || !read.IssuedAt().Equal(session.IssuedAt()) {
		t.Errorf("the instants came back as %v and %v", read.IssuedAt(), read.ExpiresAt())
	}
	if read.Binding() != binding {
		t.Error("the binding did not survive the round trip")
	}
}

func TestTwoSessionsForOneSubjectAreDifferentSessions(t *testing.T) {
	minted := issuer(t, time.Hour)
	binding := fingerprint("alice's certificate")

	first, firstToken, err := minted.Issue("alice", binding, when)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	second, secondToken, err := minted.Issue("alice", binding, when)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if first.ID() == second.ID() {
		t.Error("two sessions share an identity")
	}
	if firstToken == secondToken {
		t.Error("two sessions share a token")
	}
}

func TestATokenThisProcessDidNotMintIsRefused(t *testing.T) {
	minted := issuer(t, time.Hour)
	binding := fingerprint("alice's certificate")

	_, token, err := minted.Issue("alice", binding, when)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	payload, signature, _ := strings.Cut(token, ".")

	for name, offered := range map[string]string{
		"a token from another process": func() string {
			_, other, err := issuer(t, time.Hour).Issue("alice", binding, when)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			return other
		}(),
		"an edited payload":       flip(payload) + "." + signature,
		"an edited signature":     payload + "." + flip(signature),
		"no signature":            payload,
		"an empty token":          "",
		"a lone separator":        ".",
		"payload that is not b64": "!!!." + signature,
		"signature not b64":       payload + ".!!!",
		"a truncated payload":     payload[:len(payload)/2] + "." + signature,
		"nothing but padding": base64.RawURLEncoding.EncodeToString(make([]byte, 200)) + "." +
			base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	} {
		if _, err := minted.Verify(offered, binding, when); !errors.Is(err, authz.ErrToken) {
			t.Errorf("%s produced %v", name, err)
		}
	}
}

func flip(written string) string {
	raw, err := base64.RawURLEncoding.DecodeString(written)
	if err != nil || len(raw) == 0 {
		return written
	}
	raw[len(raw)/2] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestASessionStopsBeingSpendableWhenItSaysItDoes(t *testing.T) {
	minted := issuer(t, 15*time.Minute)
	binding := fingerprint("alice's certificate")

	session, token, err := minted.Issue("alice", binding, when)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := minted.Verify(token, binding, session.ExpiresAt().Add(-time.Millisecond)); err != nil {
		t.Errorf("a live session was refused: %v", err)
	}
	for name, at := range map[string]time.Time{
		"at the instant it expires": session.ExpiresAt(),
		"after it expires":          session.ExpiresAt().Add(time.Second),
		"much later":                session.ExpiresAt().Add(365 * 24 * time.Hour),
	} {
		if _, err := minted.Verify(token, binding, at); !errors.Is(err, authz.ErrExpired) {
			t.Errorf("%s produced %v", name, err)
		}
	}
	if !session.Expired(session.ExpiresAt()) || session.Expired(session.IssuedAt()) {
		t.Error("the session disagrees with itself about when it expires")
	}
}

func TestATokenIsWorthlessOnAnotherConnection(t *testing.T) {
	minted := issuer(t, time.Hour)

	_, token, err := minted.Issue("alice", fingerprint("alice's certificate"), when)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	for name, presented := range map[string][sha256.Size]byte{
		"another caller's certificate": fingerprint("mallory's certificate"),
		"a reissued certificate":       fingerprint("alice's second certificate"),
		"no certificate at all":        {},
	} {
		if _, err := minted.Verify(token, presented, when); !errors.Is(err, authz.ErrWrongCertificate) {
			t.Errorf("%s produced %v", name, err)
		}
	}
}

func TestOneCommonNameIsNotOneCertificate(t *testing.T) {
	first := &x509.Certificate{Raw: []byte("first"), Subject: pkix.Name{CommonName: "alice"}}
	second := &x509.Certificate{Raw: []byte("second"), Subject: pkix.Name{CommonName: "alice"}}

	if authz.Fingerprint(first) == authz.Fingerprint(second) {
		t.Error("two certificates for one name have one fingerprint")
	}
	if authz.Fingerprint(first) != authz.Fingerprint(&x509.Certificate{Raw: []byte("first")}) {
		t.Error("one certificate has two fingerprints")
	}
	if authz.Fingerprint(nil) != ([sha256.Size]byte{}) {
		t.Error("no certificate has a fingerprint")
	}
}

func TestAnIssuerRefusesWhatCannotProtectASession(t *testing.T) {
	key, err := authz.RandomSessionKey()
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}

	for name, build := range map[string]func() (*authz.Issuer, error){
		"a short key": func() (*authz.Issuer, error) { return authz.NewIssuer(key[:31], time.Hour) },
		"no key":      func() (*authz.Issuer, error) { return authz.NewIssuer(nil, time.Hour) },
		"no lifetime": func() (*authz.Issuer, error) { return authz.NewIssuer(key, 0) },
		"a lifetime backwards": func() (*authz.Issuer, error) {
			return authz.NewIssuer(key, -time.Hour)
		},
	} {
		if _, err := build(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestASessionIsMintedForSomebodyOnSomething(t *testing.T) {
	minted := issuer(t, time.Hour)

	for name, build := range map[string]func() error{
		"no subject": func() error {
			_, _, err := minted.Issue("", fingerprint("a certificate"), when)
			return err
		},
		"a subject nobody could name": func() error {
			_, _, err := minted.Issue("alice smith", fingerprint("a certificate"), when)
			return err
		},
		"no certificate": func() error {
			_, _, err := minted.Issue("alice", [sha256.Size]byte{}, when)
			return err
		},
	} {
		if err := build(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestATokenCarriesNoAuthority(t *testing.T) {
	minted := issuer(t, time.Hour)
	binding := fingerprint("bob's certificate")

	_, token, err := minted.Issue("bob", binding, when)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	payload, _, _ := strings.Cut(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, resource := range authz.Resources() {
		if strings.Contains(string(raw), resource.String()) {
			t.Errorf("the token mentions %q", resource)
		}
	}
	for _, role := range []string{"analyst", "operator", "administrator"} {
		if strings.Contains(string(raw), role) {
			t.Errorf("the token mentions the role %q", role)
		}
	}
	if !strings.Contains(string(raw), "bob") {
		t.Error("the token does not say who it is for")
	}
}
