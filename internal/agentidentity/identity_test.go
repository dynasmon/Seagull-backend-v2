package agentidentity_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/dynasmon/Seagull-v2/internal/agentidentity"
)

func certificateNamed(commonName string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: commonName}}
}

func verifiedConnection(commonName string) *tls.ConnectionState {
	return &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{certificateNamed(commonName)}},
	}
}

func TestIdentityComesFromTheVerifiedCertificate(t *testing.T) {
	identity, err := agentidentity.FromConnection(verifiedConnection("web-01"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.AgentID != "web-01" {
		t.Fatalf("unexpected identity %q", identity.AgentID)
	}
}

func TestConnectionWithoutAVerifiedChainIsRefused(t *testing.T) {
	cases := map[string]*tls.ConnectionState{
		"no tls state":  nil,
		"no chain":      {},
		"empty chain":   {VerifiedChains: [][]*x509.Certificate{}},
		"chain of none": {VerifiedChains: [][]*x509.Certificate{{}}},
	}
	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := agentidentity.FromConnection(state); !errors.Is(err, agentidentity.ErrNoClientCertificate) {
				t.Fatalf("expected a missing certificate, got %v", err)
			}
		})
	}
}

func TestMalformedCommonNameIsRefused(t *testing.T) {
	for name, commonName := range map[string]string{
		"empty":     "",
		"traversal": "../../etc/passwd",
		"spaces":    "web 01",
		"slashes":   "tenant/web-01",
		"too long":  "a123456789012345678901234567890123456789012345678901234567890123456789",
		"leading":   "-web-01",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := agentidentity.FromCertificate(certificateNamed(commonName)); !errors.Is(err, agentidentity.ErrMalformedIdentity) {
				t.Fatalf("expected a malformed identity, got %v", err)
			}
		})
	}
}

func TestAcceptedIdentifierShapes(t *testing.T) {
	for _, commonName := range []string{"web-01", "WEB01", "web.example.internal", "agent_1", "0host"} {
		if !agentidentity.Valid(commonName) {
			t.Fatalf("%q should be a usable agent identifier", commonName)
		}
	}
}
