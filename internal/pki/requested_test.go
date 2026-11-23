package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/pki"
)

func TestARequestIsNamedBeforeAnythingIsSignedForItAsSigningNamesIt(t *testing.T) {
	signing := authority(t, 30*24*time.Hour)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a P-256 key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate an RSA key: %v", err)
	}
	for name, asked := range map[string][]byte{
		"ecdsa":     requestWithKey(t, subject, p256),
		"rsa-pkcs1": requestWithKey(t, subject, rsaKey),
	} {
		named, err := pki.Requested(asked, subject)
		if err != nil {
			t.Fatalf("an %s request was refused: %v", name, err)
		}
		issued, err := signing.Sign(subject, asked, time.Hour, time.Now())
		if err != nil || issued.Request != named {
			t.Fatalf("an %s request is named %q before signing and %q by it: %v", name, named, issued.Request, err)
		}
	}
	if _, err := pki.Requested([]byte("agent-01"), subject); !errors.Is(err, pki.ErrMalformedRequest) {
		t.Errorf("a request that is not one was named, answered %v", err)
	}
	if _, err := pki.Requested(request(t, "web-02"), subject); !errors.Is(err, pki.ErrMalformedRequest) {
		t.Errorf("a request naming another agent was named, answered %v", err)
	}
}
