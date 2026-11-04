package hunt_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
)

func certificate(commonName string, organisations []string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: commonName, Organization: organisations}}
}

func verified(certificate *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
}

// analyst-01 reads both datasets in acme, auditor-01 reads detections in acme and
// globex, and nobody else is named.
func policy(t *testing.T) *authz.Policy {
	t.Helper()
	read := func(resource authz.Resource) authz.Permission {
		return authz.Permission{Resource: resource, Action: authz.Read}
	}
	analyst, err := authz.NewRole("analyst", "reads what was observed and decided", []authz.Permission{read(authz.Events), read(authz.Detections)})
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := authz.NewRole("auditor", "reads what was decided", []authz.Permission{read(authz.Detections)})
	if err != nil {
		t.Fatal(err)
	}
	var bindings []authz.Binding
	for _, bound := range []struct {
		subject string
		role    string
		tenants []string
	}{
		{subject: "analyst-01", role: "analyst", tenants: []string{"acme"}},
		{subject: "auditor-01", role: "auditor", tenants: []string{"globex", "acme"}},
	} {
		binding, err := authz.NewBinding(bound.subject, []string{bound.role}, bound.tenants)
		if err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, binding)
	}
	compiled, err := authz.Compile([]authz.Role{analyst, auditor}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// What a certificate's organisation says is never a tenant the caller may read:
// the policy alone names them, so a certificate issued before a subject lost its
// grant reads nothing more than the policy now allows.
func TestTheScopeIsWhatThePolicyGrantsTheCallerAndNeverWhatItsCertificateSays(t *testing.T) {
	granted := policy(t)
	scope, err := hunt.Authorize(verified(certificate("analyst-01", []string{"globex", "initech"})), granted, hunt.Events)
	if err != nil {
		t.Fatalf("a caller the policy lets read events was refused: %v", err)
	}
	if tenants := scope.Tenants(); !slices.Equal(tenants, []string{"acme"}) {
		t.Errorf("the scope holds %v, and the policy grants acme alone", tenants)
	}

	scope, err = hunt.Authorize(verified(certificate("auditor-01", nil)), granted, hunt.Detections)
	if err != nil || !slices.Equal(scope.Tenants(), []string{"acme", "globex"}) {
		t.Errorf("a caller granted detections in two tenants was scoped %v (%v)", scope.Tenants(), err)
	}
}

func TestACallerThePolicyDoesNotLetReadADatasetIsRefused(t *testing.T) {
	granted := policy(t)
	for name, refused := range map[string]struct {
		state   *tls.ConnectionState
		dataset hunt.Dataset
		want    error
	}{
		"no connection state":            {state: nil, dataset: hunt.Events, want: hunt.ErrNoClientCertificate},
		"no verified chain":              {state: &tls.ConnectionState{}, dataset: hunt.Events, want: hunt.ErrNoClientCertificate},
		"an empty chain":                 {state: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}, dataset: hunt.Events, want: hunt.ErrNoClientCertificate},
		"a subject the policy names not": {state: verified(certificate("intruder-01", []string{"acme"})), dataset: hunt.Events, want: hunt.ErrNotGranted},
		"events without events:read":     {state: verified(certificate("auditor-01", nil)), dataset: hunt.Events, want: hunt.ErrNotPermitted},
	} {
		if _, err := hunt.Authorize(refused.state, granted, refused.dataset); !errors.Is(err, refused.want) {
			t.Errorf("%s was answered %v, want %v", name, err, refused.want)
		}
	}
}

// A tenant no record could ever carry is a mistake in the policy rather than a
// scope that reads nothing, and it is refused where it can be seen.
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

func TestTheCallerIsNamedByItsCertificate(t *testing.T) {
	if caller := hunt.CallerFromConnection(verified(certificate("analyst-01", []string{"acme"}))); caller != "analyst-01" {
		t.Errorf("the caller is %q", caller)
	}
	if caller := hunt.CallerFromConnection(nil); caller != "" {
		t.Errorf("an unauthenticated caller is named %q", caller)
	}
}
