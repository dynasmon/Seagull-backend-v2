package authz_test

import (
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
)

func TestEveryDeclaredPermissionSaysWhetherItIsThePlatformsOrATenants(t *testing.T) {
	for _, resource := range authz.Resources() {
		for _, action := range authz.Actions() {
			permission := authz.Permission{Resource: resource, Action: action}
			if scope := permission.Scope(); scope != authz.Platform && scope != authz.Tenant {
				t.Errorf("%s is declared without saying whether it is the platform's or a tenant's", permission)
			}
		}
	}
}

// What every tenant shares is the platform's: a change to this table moves who
// may replace what detects for everybody, end anybody's session or publish what
// every agent may install, and is a decision rather than an edit.
func TestWhatEveryTenantSharesIsThePlatforms(t *testing.T) {
	platform := permissions(t,
		"rulesets:write", "rulesets:delete",
		"sessions:read", "sessions:write", "sessions:delete",
		"policies:read", "policies:write", "policies:delete",
	)
	for _, permission := range platform {
		if permission.Scope() != authz.Platform {
			t.Errorf("%s is %q, and what it reaches is shared by every tenant", permission, permission.Scope())
		}
	}

	for _, resource := range authz.Resources() {
		for _, action := range authz.Actions() {
			permission := authz.Permission{Resource: resource, Action: action}
			listed := false
			for _, one := range platform {
				listed = listed || one == permission
			}
			if !listed && permission.Scope() != authz.Tenant {
				t.Errorf("%s is %q, and nothing decided it is the platform's", permission, permission.Scope())
			}
		}
	}
}
