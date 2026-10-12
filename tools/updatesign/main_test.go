package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

var signed = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

const catalogDocument = `{
  "schemaVersion": 1,
  "version": "3",
  "releases": [{
    "version": "v0.2.0",
    "platform": {"os": "linux", "architecture": "amd64", "format": "FORMAT_DEB"},
    "source": {"repository": "github.com/dynasmon/Seagull-agent-v2", "revision": "03c12793b25f0000000000000000000000000000"},
    "compatibility": {"stateGeneration": 1}
  }]
}`

type keyPair struct {
	private, public string
}

func written(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{
		private: written(t, "private.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})),
		public:  written(t, "public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})),
	}
}

func firstRoot(t *testing.T, owner keyPair) string {
	t.Helper()
	envelope := filepath.Join(t.TempDir(), "root-1.pb")
	if err := signRoot([]string{"-version", "1", "-key", owner.private, "-root-key", owner.public,
		"-catalog-key", owner.public, "-envelope", envelope}, signed); err != nil {
		t.Fatalf("sign the first root: %v", err)
	}
	return envelope
}

func TestTheFirstRootIsWrittenAsWhatEveryVerifierIsProvisionedWith(t *testing.T) {
	owner, publisher := newKeyPair(t), newKeyPair(t)
	envelope := filepath.Join(t.TempDir(), "root.pb")
	publication := filepath.Join(t.TempDir(), "publication.pb")

	if err := signRoot([]string{"-version", "1", "-key", owner.private, "-root-key", owner.public,
		"-catalog-key", publisher.public, "-envelope", envelope, "-output", publication, "-note", "the first root"}, signed); err != nil {
		t.Fatalf("sign: %v", err)
	}
	served, err := os.ReadFile(envelope)
	if err != nil {
		t.Fatal(err)
	}
	root, err := agentupdate.Anchor(served, signed)
	if err != nil || root.Version() != 1 || len(root.Message().GetKeys()) != 2 {
		t.Fatalf("the written root is not one a verifier trusts: %v", err)
	}
	encoded, err := os.ReadFile(publication)
	if err != nil {
		t.Fatal(err)
	}
	var published updatev1.RootPublication
	if err := proto.Unmarshal(encoded, &published); err != nil || published.GetNote() != "the first root" {
		t.Fatalf("the publication does not read back: %v", err)
	}
	again, err := agentupdate.Encode(published.GetRoot())
	if err != nil || !bytes.Equal(again, served) {
		t.Fatal("the publication carries another root than the envelope written beside it")
	}
}

func TestARotationIsWrittenOnlyWhenTheChainTakesIt(t *testing.T) {
	before, after := newKeyPair(t), newKeyPair(t)
	previous := firstRoot(t, before)
	output := filepath.Join(t.TempDir(), "root-2.pb")
	rotation := func(signers ...keyPair) error {
		arguments := []string{"-version", "2", "-previous", previous, "-root-key", after.public, "-catalog-key", after.public, "-output", output}
		for _, key := range signers {
			arguments = append(arguments, "-key", key.private)
		}
		return signRoot(arguments, signed)
	}

	if err := rotation(after); !errors.Is(err, agentupdate.ErrUnsigned) {
		t.Fatalf("a root the previous one did not vouch for was written: %v", err)
	}
	if err := rotation(before, after); err != nil {
		t.Fatalf("a rotation both roots signed was refused: %v", err)
	}
	if err := signRoot([]string{"-version", "2", "-key", after.private, "-root-key", after.public, "-catalog-key", after.public, "-output", output}, signed); err == nil {
		t.Fatal("a root past version 1 was written without the root it replaces")
	}
}

func TestACatalogCarriesTheDigestOfItsPackagesAndVerifiesUnderTheNewestRoot(t *testing.T) {
	owner := newKeyPair(t)
	root := firstRoot(t, owner)
	deb := written(t, "seagull-agent_0.2.0-1_amd64.deb", []byte("!<arch>\nthe package of v0.2.0"))
	document := written(t, "catalog.json", []byte(catalogDocument))
	output := filepath.Join(t.TempDir(), "catalog.pb")

	if err := signCatalog([]string{"-catalog", document, "-package", "v0.2.0=" + deb, "-key", owner.private,
		"-root", root, "-output", output}, signed); err != nil {
		t.Fatalf("sign the catalog: %v", err)
	}
	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var published updatev1.CatalogPublication
	if err := proto.Unmarshal(encoded, &published); err != nil {
		t.Fatal(err)
	}
	served, err := os.ReadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := agentupdate.Anchor(served, signed)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := trusted.Catalog(published.GetCatalog(), signed)
	if err != nil {
		t.Fatalf("the written catalog does not verify under the root: %v", err)
	}
	content, _ := os.ReadFile(deb)
	sum := sha256.Sum256(content)
	payload := catalog.Releases()[0].GetPayload()
	if catalog.Version() != 3 || !bytes.Equal(payload.GetSha256(), sum[:]) || payload.GetSize() != uint64(len(content)) {
		t.Fatalf("catalog %d names the package as %x of %d bytes", catalog.Version(), payload.GetSha256(), payload.GetSize())
	}
	if !catalog.ExpiresAt().Equal(signed.Add(90 * 24 * time.Hour)) {
		t.Fatalf("the catalog runs out at %s", catalog.ExpiresAt())
	}
}

func TestACatalogIsNotWrittenUnlessEveryReleaseIsNamedAndItsRoleSigned(t *testing.T) {
	owner, stranger := newKeyPair(t), newKeyPair(t)
	root := firstRoot(t, owner)
	deb := written(t, "package.deb", []byte("package"))
	document := written(t, "catalog.json", []byte(catalogDocument))
	output := filepath.Join(t.TempDir(), "catalog.pb")

	for name, arguments := range map[string][]string{
		"no package for the release":     {"-catalog", document, "-key", owner.private, "-root", root, "-output", output},
		"a package for another release":  {"-catalog", document, "-package", "v0.3.0=" + deb, "-key", owner.private, "-root", root, "-output", output},
		"a package on another platform":  {"-catalog", document, "-package", "v0.2.0/linux/arm64=" + deb, "-key", owner.private, "-root", root, "-output", output},
		"a key outside the catalog role": {"-catalog", document, "-package", "v0.2.0=" + deb, "-key", stranger.private, "-root", root, "-output", output},
		"no root to check it under":      {"-catalog", document, "-package", "v0.2.0=" + deb, "-key", owner.private, "-output", output},
	} {
		if err := signCatalog(arguments, signed); err == nil {
			t.Errorf("%s: the catalog was written", name)
		}
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused catalog left a publication behind: %v", err)
	}
}
