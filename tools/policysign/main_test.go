package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const document = `{
  "schemaVersion": 1,
  "policyId": "linux-web",
  "revision": "7",
  "targets": {"agentIds": ["web-01", "web-02"]},
  "settings": {
    "logLevel": "LOG_LEVEL_WARN",
    "modules": [{"module": "MODULE_PROCESSES", "collection": "COLLECTION_ENABLED", "interval": "3600s"}],
    "budgets": {"spoolMaxBytes": "268435456"}
  }
}`

var signed = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func written(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func keyFile(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encode the key: %v", err)
	}
	return written(t, "signer.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), key
}

func accepting(t *testing.T, keys ...*ecdsa.PrivateKey) *agentpolicy.Signers {
	t.Helper()
	var encoded []byte
	for _, key := range keys {
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("encode a public key: %v", err)
		}
		encoded = append(encoded, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...)
	}
	signers, err := agentpolicy.ParseSigners(encoded)
	if err != nil {
		t.Fatalf("read the signers: %v", err)
	}
	return signers
}

func TestASignedPublicationIsWhatThePlatformAccepts(t *testing.T) {
	previous, previousKey := keyFile(t)
	next, nextKey := keyFile(t)
	output := filepath.Join(t.TempDir(), "publication.pb")

	if err := run([]string{previous, next}, written(t, "policy.json", []byte(document)), "default", "quieter web servers",
		90*24*time.Hour, output, signed); err != nil {
		t.Fatalf("sign: %v", err)
	}

	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read the publication: %v", err)
	}
	var publication policyv1.Publication
	if err := proto.Unmarshal(content, &publication); err != nil {
		t.Fatalf("decode the publication: %v", err)
	}
	if publication.GetTenantId() != "default" || publication.GetNote() != "quieter web servers" {
		t.Fatalf("the publication is %v", &publication)
	}
	for _, accepted := range [][]*ecdsa.PrivateKey{{previousKey}, {nextKey}} {
		taken, err := agentpolicy.Accept(&publication, accepting(t, accepted...), "dev-admin", signed.Add(time.Minute))
		if err != nil {
			t.Fatalf("the platform refused what was signed: %v", err)
		}
		policy, err := accepting(t, accepted...).Verify(publication.GetPolicy())
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if taken.Record.GetRevision() != 7 || !policy.Policy.GetIssuedAt().AsTime().Equal(signed) ||
			!policy.Policy.GetExpiresAt().AsTime().Equal(signed.Add(90*24*time.Hour)) ||
			!slices.Equal(taken.Targets, []string{"web-01", "web-02"}) {
			t.Fatalf("the signed policy reads %v", policy.Policy)
		}
	}
}

func TestNothingIsWrittenForAPolicyThePlatformWouldRefuse(t *testing.T) {
	signer, _ := keyFile(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate an RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatalf("encode the RSA key: %v", err)
	}
	rsaKey := written(t, "rsa.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	policy := written(t, "policy.json", []byte(document))

	for name, attempt := range map[string]func(output string) error{
		"no expiry": func(output string) error {
			return run([]string{signer}, policy, "default", "", 0, output, signed)
		},
		"an RSA key": func(output string) error {
			return run([]string{rsaKey}, policy, "default", "", time.Hour, output, signed)
		},
		"a document that is not a policy": func(output string) error {
			return run([]string{signer}, written(t, "other.json", []byte(`{"revision": "seven"}`)), "default", "", time.Hour, output, signed)
		},
		"no tenant": func(output string) error {
			return run([]string{signer}, policy, "", "", time.Hour, output, signed)
		},
		"a life beyond a year": func(output string) error {
			return run([]string{signer}, policy, "default", "", 400*24*time.Hour, output, signed)
		},
	} {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "publication.pb")
			if err := attempt(output); err == nil {
				t.Fatal("a policy the platform would refuse was signed")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused policy left %s behind: %v", output, err)
			}
		})
	}
}
