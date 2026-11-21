package pki_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
	"github.com/dynasmon/Seagull-backend-v2/internal/pki"
)

func TestAuthoritiesReadsEveryAuthorityInABundle(t *testing.T) {
	current, err := devpki.NewAuthority("Seagull Current Agent CA", time.Hour)
	if err != nil {
		t.Fatalf("build the current authority: %v", err)
	}
	next, err := devpki.NewAuthority("Seagull Next Agent CA", time.Hour)
	if err != nil {
		t.Fatalf("build the next authority: %v", err)
	}

	bundle := append(append([]byte(nil), current.Material().CertificatePEM...), next.Material().CertificatePEM...)
	authorities, err := pki.Authorities(bundle)
	if err != nil {
		t.Fatalf("read a bundle of two authorities: %v", err)
	}
	if len(authorities) != 2 {
		t.Fatalf("a bundle of two authorities read %d", len(authorities))
	}
}

func TestAuthoritiesRefusesABundleAnAgentCouldNotVerifyWith(t *testing.T) {
	signing, err := devpki.NewAuthority("Seagull Agent CA", time.Hour)
	if err != nil {
		t.Fatalf("build an authority: %v", err)
	}
	leaf, err := signing.IssueClient("agent-01", time.Hour)
	if err != nil {
		t.Fatalf("issue a leaf: %v", err)
	}

	for name, bundle := range map[string][]byte{
		"nothing at all":       nil,
		"not PEM":              []byte("Seagull Agent CA"),
		"a leaf certificate":   leaf.CertificatePEM,
		"a private key":        signing.Material().PrivateKeyPEM,
		"longer than allowed":  []byte(strings.Repeat("a", pki.MaxBundleBytes+1)),
		"an authority and key": append(append([]byte(nil), signing.Material().CertificatePEM...), signing.Material().PrivateKeyPEM...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pki.Authorities(bundle); !errors.Is(err, pki.ErrMalformedBundle) {
				t.Fatalf("%s was accepted, or refused with %v", name, err)
			}
		})
	}
}

// The half of a rotation that cannot be skipped: an agent handed a bundle
// without the authority that signs stops trusting the platform on renewal.
func TestTrustsRefusesABundleWithoutTheSigningAuthority(t *testing.T) {
	signing := authority(t, time.Hour)
	other, err := devpki.NewAuthority("Seagull Other Agent CA", time.Hour)
	if err != nil {
		t.Fatalf("build another authority: %v", err)
	}
	if err := pki.Trusts(other.Material().CertificatePEM, signing); !errors.Is(err, pki.ErrMalformedBundle) {
		t.Fatalf("a bundle missing the signing authority was answered with %v", err)
	}
	if err := pki.Trusts(signing.Chain(), signing); err != nil {
		t.Fatalf("a bundle carrying the signing authority was refused: %v", err)
	}
}

// On 2026-11-20 a second mint of the development material left a running
// plane signing under one authority and publishing another of the same name,
// and the refusal named the same authority on both sides.
func TestARefusedBundleTellsApartAuthoritiesOfOneName(t *testing.T) {
	signing := authority(t, time.Hour)
	minted, err := devpki.NewAuthority(signing.Subject(), time.Hour)
	if err != nil {
		t.Fatalf("build another authority of the same name: %v", err)
	}
	err = pki.Trusts(minted.Material().CertificatePEM, signing)
	if !errors.Is(err, pki.ErrMalformedBundle) {
		t.Fatalf("a bundle missing the signing authority was answered with %v", err)
	}
	for name, held := range map[string][]byte{"signing": signing.Chain(), "carried": minted.Material().CertificatePEM} {
		block, _ := pem.Decode(held)
		digest := sha256.Sum256(block.Bytes)
		if !strings.Contains(err.Error(), hex.EncodeToString(digest[:])) {
			t.Errorf("the refusal %q does not tell the %s authority apart by its digest", err, name)
		}
	}
}
