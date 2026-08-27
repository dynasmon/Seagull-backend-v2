package hunt_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
)

func certificate(commonName string, tenants []string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: commonName, Organization: tenants}}
}

func verified(certificate *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
}

func TestTheScopeComesFromTheCertificate(t *testing.T) {
	scope, err := hunt.ScopeFromConnection(verified(certificate("analyst-01", []string{"acme", "globex"})))
	if err != nil {
		t.Fatalf("read the scope: %v", err)
	}
	if tenants := scope.Tenants(); !slices.Equal(tenants, []string{"acme", "globex"}) {
		t.Errorf("the scope holds %v", tenants)
	}
}

// A connection nobody authenticated has no scope, and an empty scope reads
// nothing rather than everything.
func TestAnUnauthenticatedCallerHasNoScope(t *testing.T) {
	for name, state := range map[string]*tls.ConnectionState{
		"no connection state": nil,
		"no verified chain":   {},
		"an empty chain":      {VerifiedChains: [][]*x509.Certificate{{}}},
	} {
		if _, err := hunt.ScopeFromConnection(state); !errors.Is(err, hunt.ErrNoClientCertificate) {
			t.Errorf("%s produced %v", name, err)
		}
	}
}

func TestACertificateNamingNoTenantIsRefused(t *testing.T) {
	if _, err := hunt.ScopeFromConnection(verified(certificate("analyst-01", nil))); !errors.Is(err, hunt.ErrNoScope) {
		t.Errorf("a certificate with no organisation produced %v", err)
	}
}

// A tenant no record could ever carry is a mistake in the certificate rather
// than a scope that reads nothing, and it is refused where it can be seen.
func TestATenantTheStoreCouldNeverHoldIsRefused(t *testing.T) {
	if _, err := hunt.NewScope([]string{"acme", "not a tenant/../.."}); err == nil {
		t.Error("a scope was built from an identifier no record can carry")
	}
}

func TestTheSameTenantTwiceIsOneTenant(t *testing.T) {
	scope, err := hunt.NewScope([]string{"globex", "acme", "globex"})
	if err != nil {
		t.Fatalf("build the scope: %v", err)
	}
	if tenants := scope.Tenants(); !slices.Equal(tenants, []string{"acme", "globex"}) {
		t.Errorf("the scope holds %v", tenants)
	}
}

func TestTheCallerIsNamedForTheLogOnly(t *testing.T) {
	if caller := hunt.CallerFromConnection(verified(certificate("analyst-01", []string{"acme"}))); caller != "analyst-01" {
		t.Errorf("the caller is %q", caller)
	}
	if caller := hunt.CallerFromConnection(nil); caller != "" {
		t.Errorf("an unauthenticated caller is named %q", caller)
	}
}
