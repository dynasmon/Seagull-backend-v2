package devpki

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func authorityFor(t *testing.T, name string) *Authority {
	t.Helper()
	authority, err := NewAuthority(name, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func TestAKeptCertificateIsTheOneIssuedForWhatIsAsked(t *testing.T) {
	authority, other := authorityFor(t, "kept"), authorityFor(t, "other")
	server, err := authority.IssueServer("ingest-gateway", []string{"ingest-gateway", "localhost", "127.0.0.1"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.IssueServer("ingest-gateway", []string{"ingest-gateway", "localhost", "127.0.0.1"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := authority.IssueCaller("dev-analyst", []string{"default"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	asked := Leaf{CommonName: "ingest-gateway", Hosts: []string{"ingest-gateway", "127.0.0.1"}, Usage: x509.ExtKeyUsageServerAuth}

	if err := Keeps(authority.Material(), server, asked, now, time.Hour); err != nil {
		t.Fatalf("the certificate issued for what is asked was refused: %v", err)
	}
	for name, refused := range map[string]struct {
		leaf   Material
		wanted Leaf
		at     time.Time
	}{
		"another authority's":       {foreign, asked, now},
		"another name":              {server, Leaf{CommonName: "control-api", Hosts: asked.Hosts, Usage: asked.Usage}, now},
		"another use":               {server, Leaf{CommonName: "ingest-gateway", Usage: x509.ExtKeyUsageClientAuth}, now},
		"a host it does not cover":  {server, Leaf{CommonName: "ingest-gateway", Hosts: []string{"192.0.2.10"}, Usage: asked.Usage}, now},
		"another tenant":            {caller, Leaf{CommonName: "dev-analyst", Organisation: []string{"globex"}, Usage: x509.ExtKeyUsageClientAuth}, now},
		"inside the margin":         {server, asked, now.Add(23*time.Hour + 30*time.Minute)},
		"a key that is not its own": {Material{CertificatePEM: server.CertificatePEM, PrivateKeyPEM: foreign.PrivateKeyPEM}, asked, now},
		"nothing written":           {Material{}, asked, now},
	} {
		if err := Keeps(authority.Material(), refused.leaf, refused.wanted, refused.at, time.Hour); err == nil {
			t.Errorf("a certificate of %s was kept", name)
		}
	}
	if err := Keeps(authority.Material(), caller, Leaf{CommonName: "dev-analyst", Organisation: []string{"default"}, Usage: x509.ExtKeyUsageClientAuth}, now, time.Hour); err != nil {
		t.Errorf("the caller issued for its tenant was refused: %v", err)
	}
}

func TestAnAuthorityIsTakenBackOnlyWithItsOwnKey(t *testing.T) {
	authority, other := authorityFor(t, "kept"), authorityFor(t, "other")
	now := time.Now()

	loaded, err := LoadAuthority(authority.Material(), now, time.Hour)
	if err != nil {
		t.Fatalf("the authority was not taken back: %v", err)
	}
	issued, err := loaded.IssueClient("dev-agent-01", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := Keeps(authority.Material(), issued, Leaf{CommonName: "dev-agent-01", Usage: x509.ExtKeyUsageClientAuth}, now, time.Hour); err != nil {
		t.Errorf("what the authority taken back signs is not trusted under the one it was: %v", err)
	}

	leaf, err := authority.IssueClient("dev-agent-01", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, material := range map[string]Material{
		"another authority's key": {CertificatePEM: authority.Material().CertificatePEM, PrivateKeyPEM: other.Material().PrivateKeyPEM},
		"a leaf":                  leaf,
		"no key":                  {CertificatePEM: authority.Material().CertificatePEM},
	} {
		if _, err := LoadAuthority(material, now, time.Hour); err == nil {
			t.Errorf("an authority with %s was taken back", name)
		}
	}
	if _, err := LoadAuthority(authority.Material(), now.Add(47*time.Hour+30*time.Minute), time.Hour); err == nil {
		t.Error("an authority inside the margin was taken back")
	}
}

func TestATrustBundleCarriesTheAuthorityAmongOthers(t *testing.T) {
	authority, other := authorityFor(t, "kept"), authorityFor(t, "other")
	widened := string(other.Material().CertificatePEM) + string(authority.Material().CertificatePEM)

	if !Carries([]byte(widened), authority.Material()) {
		t.Error("a bundle holding the authority second does not carry it")
	}
	if Carries(other.Material().CertificatePEM, authority.Material()) || Carries(nil, authority.Material()) {
		t.Error("a bundle without the authority carries it")
	}
	if Carries([]byte(strings.Replace(widened, "CERTIFICATE", "PUBLIC KEY", -1)), authority.Material()) {
		t.Error("a block that is not a certificate carries the authority")
	}
}
