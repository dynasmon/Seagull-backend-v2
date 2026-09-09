package pki_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/pki"
)

func requestWithKey(t *testing.T, commonName string, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatalf("create a certificate request: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSignAcceptsEveryKeyTheContractOffers(t *testing.T) {
	signing := authority(t, 30*24*time.Hour)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate an RSA key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate an Ed25519 key: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a P-384 key: %v", err)
	}

	for name, key := range map[string]any{"rsa-2048": rsaKey, "ed25519": edKey, "ecdsa-p384": p384} {
		t.Run(name, func(t *testing.T) {
			if _, err := signing.Sign(subject, requestWithKey(t, subject, key), time.Hour, time.Now()); err != nil {
				t.Fatalf("a %s request was refused: %v", name, err)
			}
		})
	}
}

func TestSignRefusesAKeyBelowWhatIsOffered(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate a weak RSA key: %v", err)
	}
	_, err = authority(t, 30*24*time.Hour).Sign(subject, requestWithKey(t, subject, weak), time.Hour, time.Now())
	if !errors.Is(err, pki.ErrMalformedRequest) {
		t.Fatalf("a 1024 bit key was answered with %v", err)
	}
}

func TestSignRefusesARequestThatIsNotOne(t *testing.T) {
	signing := authority(t, 30*24*time.Hour)
	valid := request(t, subject)
	block, _ := pem.Decode(valid)

	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-1] ^= 0xff

	for name, requestPEM := range map[string][]byte{
		"nothing at all":      nil,
		"not PEM":             []byte("agent-01"),
		"the wrong PEM type":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		"two blocks":          append(append([]byte(nil), valid...), valid...),
		"a broken signature":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}),
		"longer than allowed": []byte(strings.Repeat("a", pki.MaxRequestBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := signing.Sign(subject, requestPEM, time.Hour, time.Now()); !errors.Is(err, pki.ErrMalformedRequest) {
				t.Fatalf("%s was answered with %v", name, err)
			}
		})
	}
}
