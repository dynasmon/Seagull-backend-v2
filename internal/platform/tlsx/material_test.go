package tlsx_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/tlsx"
)

type bundle struct {
	certificate string
	key         string
	authority   string
}

func issue(t *testing.T, directory, commonName string) (*devpki.Authority, bundle) {
	t.Helper()

	authority, err := devpki.NewAuthority("Test CA", time.Hour)
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	server, err := authority.IssueServer(commonName, []string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}

	paths := bundle{
		certificate: filepath.Join(directory, "server.pem"),
		key:         filepath.Join(directory, "server-key.pem"),
		authority:   filepath.Join(directory, "ca.pem"),
	}
	writeFile(t, paths.certificate, server.CertificatePEM)
	writeFile(t, paths.key, server.PrivateKeyPEM)
	writeFile(t, paths.authority, authority.Material().CertificatePEM)
	return authority, paths
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestMissingMaterialFailsAtConstruction(t *testing.T) {
	if _, err := tlsx.NewMaterial("", "", ""); err == nil {
		t.Fatal("a listener without material must not be built")
	}
	if _, err := tlsx.NewMaterial("/nonexistent/cert.pem", "/nonexistent/key.pem", ""); err == nil {
		t.Fatal("unreadable material must fail at construction")
	}
}

func TestMutualConfigurationRequiresAnAuthority(t *testing.T) {
	_, paths := issue(t, t.TempDir(), "server")

	material, err := tlsx.NewMaterial(paths.certificate, paths.key, "")
	if err != nil {
		t.Fatalf("load material: %v", err)
	}
	if _, err := material.MutualServerConfig(); err == nil {
		t.Fatal("mutual TLS without a client authority must be refused")
	}
}

func TestServerConfigurationDemandsModernTLSAndVerifiedClients(t *testing.T) {
	_, paths := issue(t, t.TempDir(), "server")

	material, err := tlsx.NewMaterial(paths.certificate, paths.key, paths.authority)
	if err != nil {
		t.Fatalf("load material: %v", err)
	}
	configuration, err := material.MutualServerConfig()
	if err != nil {
		t.Fatalf("build mutual configuration: %v", err)
	}

	if configuration.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3 as the floor, got %x", configuration.MinVersion)
	}
	if configuration.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected verified client certificates, got %v", configuration.ClientAuth)
	}
}

// A renewed certificate has to be picked up without restarting a listener that
// agents depend on.
func TestRenewedCertificateIsPickedUpWithoutARestart(t *testing.T) {
	directory := t.TempDir()
	authority, paths := issue(t, directory, "server-before")

	material, err := tlsx.NewMaterial(paths.certificate, paths.key, paths.authority)
	if err != nil {
		t.Fatalf("load material: %v", err)
	}

	before, err := material.Certificate()
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	if commonNameOf(t, before) != "server-before" {
		t.Fatalf("unexpected initial certificate %q", commonNameOf(t, before))
	}

	renewed, err := authority.IssueServer("server-after", []string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("renew certificate: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	writeFile(t, paths.certificate, renewed.CertificatePEM)
	writeFile(t, paths.key, renewed.PrivateKeyPEM)

	after, err := material.Certificate()
	if err != nil {
		t.Fatalf("read renewed certificate: %v", err)
	}
	if commonNameOf(t, after) != "server-after" {
		t.Fatalf("the renewed certificate was not picked up: %q", commonNameOf(t, after))
	}
}

func TestUnchangedCertificateIsNotReloaded(t *testing.T) {
	_, paths := issue(t, t.TempDir(), "server")

	material, err := tlsx.NewMaterial(paths.certificate, paths.key, paths.authority)
	if err != nil {
		t.Fatalf("load material: %v", err)
	}

	first, err := material.Certificate()
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	second, err := material.Certificate()
	if err != nil {
		t.Fatalf("read certificate again: %v", err)
	}
	if first != second {
		t.Fatal("an unchanged certificate was parsed twice")
	}
}

func TestAuthorityWithoutACertificateIsRefused(t *testing.T) {
	directory := t.TempDir()
	_, paths := issue(t, directory, "server")
	writeFile(t, paths.authority, []byte("not a certificate"))

	if _, err := tlsx.NewMaterial(paths.certificate, paths.key, paths.authority); err == nil {
		t.Fatal("an authority file holding no certificate must be refused")
	}
}

func commonNameOf(t *testing.T, certificate *tls.Certificate) string {
	t.Helper()
	if certificate.Leaf != nil {
		return certificate.Leaf.Subject.CommonName
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf.Subject.CommonName
}
