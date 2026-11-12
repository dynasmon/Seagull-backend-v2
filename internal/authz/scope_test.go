package authz_test

import (
	"errors"
	"strings"
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
		"releases:read", "releases:write", "releases:delete",
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

func TestABindingSaysWhatItReaches(t *testing.T) {
	for name, scope := range map[string]authz.Scope{
		"no scope":        "",
		"an unknown word": "global",
		"a near miss":     "Platform",
		"a plural":        "tenants",
	} {
		if _, err := authz.NewBinding("alice", scope, []string{"analyst"}, []string{"acme"}); err == nil {
			t.Errorf("a binding with %s was accepted", name)
		}
	}

	for _, scope := range []authz.Scope{authz.Platform, authz.Tenant} {
		built, err := authz.NewBinding("alice", scope, []string{"analyst"}, []string{"acme"})
		if err != nil {
			t.Fatalf("bind under %q: %v", scope, err)
		}
		if built.Scope() != scope {
			t.Errorf("a binding written %q reports %q", scope, built.Scope())
		}
	}
}

func TestATenantBindingCarryingAPlatformPermissionIsRefused(t *testing.T) {
	roles := []authz.Role{
		role(t, "analyst", "events:read", "rulesets:read"),
		role(t, "administrator", "agents:write", "sessions:delete"),
		role(t, "engineer", "agents:read", "alerts:read", "rulesets:write"),
	}

	for holder, held := range map[string]string{"administrator": "sessions:delete", "engineer": "rulesets:write"} {
		_, err := authz.Compile(roles, []authz.Binding{
			binding(t, "alice", authz.Tenant, []string{"analyst"}, []string{"acme"}),
			binding(t, "mallory", authz.Tenant, []string{"analyst", holder}, []string{"globex", "initech"}),
		})
		if err == nil {
			t.Fatalf("a binding of its tenants holding %s compiled", held)
		}
		if !errors.Is(err, authz.ErrPlatformPermission) {
			t.Errorf("the refusal %q is not the one a platform permission gets", err)
		}
		for _, want := range []string{"mallory", holder, held} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal %q does not name %q", err, want)
			}
		}
	}

	if _, err := authz.Compile(roles, []authz.Binding{
		binding(t, "alice", authz.Tenant, []string{"analyst"}, []string{"acme"}),
		binding(t, "root", authz.Platform, []string{"analyst", "administrator", "engineer"}, []string{"globex"}),
	}); err != nil {
		t.Errorf("the same roles bound to the platform were refused: %v", err)
	}
}

func TestEveryPlatformPermissionIsRefusedToATenantBinding(t *testing.T) {
	for _, resource := range authz.Resources() {
		for _, action := range authz.Actions() {
			permission := authz.Permission{Resource: resource, Action: action}
			_, err := authz.Compile(
				[]authz.Role{role(t, "holder", permission.String())},
				[]authz.Binding{binding(t, "alice", authz.Tenant, []string{"holder"}, []string{"acme"})},
			)
			if refused := err != nil; refused != (permission.Scope() == authz.Platform) {
				t.Errorf("%s, which is %q, bound to one tenant: %v", permission, permission.Scope(), err)
			}
		}
	}
}

func TestOnlyABindingOfThePlatformMayNameNoTenant(t *testing.T) {
	if _, err := authz.NewBinding("alice", authz.Tenant, []string{"analyst"}, nil); err == nil {
		t.Error("a binding reaching only the tenants it lists listed none and was accepted")
	}

	compiled, err := authz.Compile(
		[]authz.Role{role(t, "publisher", "rulesets:read", "rulesets:write", "events:read")},
		[]authz.Binding{binding(t, "root", authz.Platform, []string{"publisher"}, nil)},
	)
	if err != nil {
		t.Fatalf("a binding of the platform naming no tenant was refused: %v", err)
	}
	root, err := compiled.Grant("root")
	if err != nil {
		t.Fatalf("grant for root: %v", err)
	}

	if decision := root.Decide(authz.Permission{Resource: authz.Rulesets, Action: authz.Write}); !decision.Allowed() {
		t.Errorf("a grant of the platform was refused rulesets:write: %q", decision.Reason)
	}
	if len(root.Tenants()) != 0 || root.Within("acme") || root.Within("") {
		t.Errorf("a grant naming no tenant covers %v", root.Tenants())
	}
	for _, tenant := range []string{"acme", "default", "", "*"} {
		decision := root.DecideWithin(authz.Permission{Resource: authz.Events, Action: authz.Read}, tenant)
		if decision.Allowed() || decision.Reason != authz.OutOfTenant {
			t.Errorf("a grant of the platform naming no tenant read events of %q: %q", tenant, decision.Reason)
		}
	}
}

func TestReachingThePlatformIsNotReachingEveryTenant(t *testing.T) {
	compiled, err := authz.Compile(
		[]authz.Role{role(t, "administrator", "agents:write", "events:read", "sessions:delete")},
		[]authz.Binding{binding(t, "root", authz.Platform, []string{"administrator"}, []string{"acme"})},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	root, err := compiled.Grant("root")
	if err != nil {
		t.Fatalf("grant for root: %v", err)
	}
	if root.Scope() != authz.Platform {
		t.Errorf("a grant bound to the platform reports %q", root.Scope())
	}

	write := authz.Permission{Resource: authz.Agents, Action: authz.Write}
	if decision := root.DecideWithin(write, "acme"); !decision.Allowed() {
		t.Errorf("root was refused the tenant it names: %q", decision.Reason)
	}
	if decision := root.DecideWithin(write, "globex"); decision.Allowed() || decision.Reason != authz.OutOfTenant {
		t.Errorf("a grant of the platform wrote agents of a tenant it does not name: %q", decision.Reason)
	}
}

func TestAGrantOfATenantSaysSo(t *testing.T) {
	alice, err := policy(t).Grant("alice")
	if err != nil {
		t.Fatalf("grant for alice: %v", err)
	}
	if alice.Scope() != authz.Tenant {
		t.Errorf("a grant bound to its tenants reports %q", alice.Scope())
	}
	if scope := (authz.Grant{}).Scope(); scope != "" {
		t.Errorf("the zero grant reports %q", scope)
	}
}

func TestWhatABindingReachesIsPartOfWhatAPolicyIs(t *testing.T) {
	roles := []authz.Role{role(t, "analyst", "events:read")}
	bound, err := authz.Compile(roles, []authz.Binding{binding(t, "alice", authz.Tenant, []string{"analyst"}, []string{"acme"})})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	raised, err := authz.Compile(roles, []authz.Binding{binding(t, "alice", authz.Platform, []string{"analyst"}, []string{"acme"})})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if bound.ID() == raised.ID() {
		t.Error("moving a binding to the platform did not change the policy identity")
	}
}
