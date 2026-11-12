package e2e_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/policyfile"
)

// The binding the 2026-11-09 integration audit wrote: the role that administers
// the platform, bound to one tenant. It is refused where it is read, so no
// process starts deciding by it.
func TestThePolicyTheIntegrationAuditWroteIsNotLoaded(t *testing.T) {
	audited := strings.Replace(controlPolicy,
		"    roles: [administrator]\n    scope: platform\n    tenants: [default]",
		"    roles: [administrator]\n    scope: tenant\n    tenants: [another-tenant]", 1)
	if audited == controlPolicy {
		t.Fatal("the administrator's binding was not found to rewrite")
	}

	_, err := policyfile.Read("policy.yml", []byte(audited))
	if err == nil {
		t.Fatal("an administrator of the platform bound to one tenant was loaded")
	}
	if !errors.Is(err, authz.ErrPlatformPermission) || !strings.Contains(err.Error(), "e2e-admin") {
		t.Errorf("the refusal %q does not name the binding and why", err)
	}
}
