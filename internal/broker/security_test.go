package broker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

func authenticated(user, password string) Security {
	return Security{TLS: true, Mechanism: MechanismScramSHA256, User: user, Password: config.Secret(password)}
}

func TestPlaintextIsAPostureAndNotAnAccident(t *testing.T) {
	var plain Security

	if err := plain.Validate(); err != nil {
		t.Fatalf("a development backbone was refused: %v", err)
	}
	if plain.Encrypted() || plain.Authenticated() {
		t.Error("a backbone with nothing configured reported itself as secured")
	}
}

// Credentials on a plaintext connection are read by anything on the path, so
// the combination is refused rather than left to a deployment to notice.
func TestAuthenticatingOverPlaintextIsRefused(t *testing.T) {
	over := authenticated("seagull", "hunter2")
	over.TLS = false

	if err := over.Validate(); err == nil {
		t.Error("a password was allowed to cross the network in the clear")
	}
}

func TestHalfAnAuthenticationIsRefused(t *testing.T) {
	cases := map[string]Security{
		"a mechanism with no user":  {TLS: true, Mechanism: MechanismScramSHA512},
		"a user with no password":   {TLS: true, Mechanism: MechanismScramSHA256, User: "seagull"},
		"a user with no mechanism":  {TLS: true, User: "seagull"},
		"tls material with tls off": {CAFile: "authority.pem"},
		"a certificate with no key": {TLS: true, CertFile: "client.pem"},
		"a key with no certificate": {TLS: true, KeyFile: "client-key.pem"},
	}

	for name, held := range cases {
		if err := held.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestASecuredBackboneCarriesItsOptionsIntoEveryClient(t *testing.T) {
	held := authenticated("seagull", "hunter2")

	options, err := held.options()
	if err != nil {
		t.Fatalf("a secured backbone was refused: %v", err)
	}
	if len(options) != 2 {
		t.Errorf("a secured backbone contributes %d client options, want tls and a mechanism", len(options))
	}
	if !held.Encrypted() || !held.Authenticated() {
		t.Error("a secured backbone did not report itself as secured")
	}
}

func TestAnAuthorityThatCarriesNoCertificateIsRefused(t *testing.T) {
	directory := t.TempDir()
	empty := filepath.Join(directory, "authority.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write a file: %v", err)
	}

	if _, err := (Security{TLS: true, CAFile: empty}).options(); err == nil {
		t.Error("a file carrying no certificate was accepted as an authority")
	}
}

func TestTheMechanismsOnOfferAreTheOnesTheParserAdmits(t *testing.T) {
	for _, mechanism := range []string{MechanismNone, MechanismScramSHA256, MechanismScramSHA512} {
		user, password := "", ""
		if mechanism != MechanismNone {
			user, password = "seagull", "hunter2"
		}
		t.Setenv("SEAGULL_BACKBONE_SASL_MECHANISM", mechanism)
		t.Setenv("SEAGULL_BACKBONE_TLS", "true")
		t.Setenv("SEAGULL_BACKBONE_SASL_USER", user)
		t.Setenv("SEAGULL_BACKBONE_SASL_PASSWORD", password)

		parser := config.FromEnvironment()
		held := LoadSecurity(parser)
		if err := parser.Err(); err != nil {
			t.Fatalf("%s was refused by the parser: %v", mechanism, err)
		}
		if _, err := held.options(); err != nil {
			t.Errorf("%s was refused: %v", mechanism, err)
		}
	}
}
