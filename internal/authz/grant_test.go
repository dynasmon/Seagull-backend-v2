package authz_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
)

func TestTheZeroGrantAllowsNothingAtAll(t *testing.T) {
	var nobody authz.Grant

	if !nobody.Empty() {
		t.Fatal("the zero grant does not report itself empty")
	}
	for _, resource := range authz.Resources() {
		for _, action := range authz.Actions() {
			permission := authz.Permission{Resource: resource, Action: action}

			if decision := nobody.Decide(permission); decision.Allowed() || decision.Reason != authz.NoGrant {
				t.Errorf("the zero grant answered %q for %s", decision.Reason, permission)
			}
			if decision := nobody.DecideWithin(permission, "acme"); decision.Allowed() {
				t.Errorf("the zero grant allowed %s in a tenant", permission)
			}
			if nobody.Allows(permission) {
				t.Errorf("the zero grant allows %s", permission)
			}
		}
	}
	if nobody.Within("acme") {
		t.Error("the zero grant covers a tenant")
	}
}

func TestASubjectNobodyBoundGetsNoGrant(t *testing.T) {
	_, err := policy(t).Grant("mallory")
	if !errors.Is(err, authz.ErrUnknownSubject) {
		t.Fatalf("an unbound subject produced %v", err)
	}
}

func TestAGrantAllowsExactlyWhatItsRolesAllowAndNothingElse(t *testing.T) {
	compiled := policy(t)

	expected := map[string][]string{
		"alice": {"detections:read", "events:read"},
		"bob":   {"detections:read", "events:read", "rulesets:read", "rulesets:write"},
	}

	for subject, allowed := range expected {
		grant, err := compiled.Grant(subject)
		if err != nil {
			t.Fatalf("grant for %q: %v", subject, err)
		}
		if grant.Subject() != subject {
			t.Errorf("the grant for %q names %q", subject, grant.Subject())
		}

		var held []string
		for _, permission := range grant.Permissions() {
			held = append(held, permission.String())
		}
		if !slices.Equal(held, allowed) {
			t.Errorf("%q holds %v, expected %v", subject, held, allowed)
		}

		for _, resource := range authz.Resources() {
			for _, action := range authz.Actions() {
				permission := authz.Permission{Resource: resource, Action: action}
				want := slices.Contains(allowed, permission.String())

				decision := grant.Decide(permission)
				if decision.Allowed() != want {
					t.Errorf("%q against %s answered %q, expected allowed=%v", subject, permission, decision.Reason, want)
				}
				if !want && decision.Reason != authz.NoPermission {
					t.Errorf("%q was refused %s for %q rather than for holding no such permission", subject, permission, decision.Reason)
				}
			}
		}
	}
}

func TestTwoRolesOnOneSubjectAreAUnion(t *testing.T) {
	compiled := policy(t)

	alice, err := compiled.Grant("alice")
	if err != nil {
		t.Fatalf("grant for alice: %v", err)
	}
	bob, err := compiled.Grant("bob")
	if err != nil {
		t.Fatalf("grant for bob: %v", err)
	}

	for _, permission := range alice.Permissions() {
		if !bob.Allows(permission) {
			t.Errorf("bob holds the analyst role and is refused %s", permission)
		}
	}
	if !slices.Equal(bob.Roles(), []string{"analyst", "operator"}) {
		t.Errorf("bob holds %v", bob.Roles())
	}
}

func TestHoldingAPermissionIsNotHoldingItEverywhere(t *testing.T) {
	compiled := policy(t)
	alice, err := compiled.Grant("alice")
	if err != nil {
		t.Fatalf("grant for alice: %v", err)
	}

	read := authz.Permission{Resource: authz.Events, Action: authz.Read}

	if decision := alice.DecideWithin(read, "acme"); !decision.Allowed() {
		t.Errorf("alice was refused her own tenant: %q", decision.Reason)
	}
	for name, tenant := range map[string]string{
		"another tenant": "globex",
		"no tenant":      "",
		"a near miss":    "acme ",
	} {
		decision := alice.DecideWithin(read, tenant)
		if decision.Allowed() {
			t.Errorf("alice read events in %s", name)
		}
		if decision.Reason != authz.OutOfTenant {
			t.Errorf("alice was refused %s for %q rather than for the tenant", name, decision.Reason)
		}
	}

	if !alice.Within("acme") || alice.Within("globex") || alice.Within("") {
		t.Errorf("alice covers %v", alice.Tenants())
	}
}

func TestAPermissionNobodyDeclaredIsRefusedAndSaysSo(t *testing.T) {
	bob, err := policy(t).Grant("bob")
	if err != nil {
		t.Fatalf("grant for bob: %v", err)
	}

	for name, permission := range map[string]authz.Permission{
		"an unknown resource": {Resource: "secrets", Action: authz.Read},
		"an unknown action":   {Resource: authz.Rulesets, Action: "approve"},
		"the zero permission": {},
	} {
		decision := bob.Decide(permission)
		if decision.Allowed() {
			t.Errorf("%s was allowed", name)
		}
		if decision.Reason != authz.Undeclared {
			t.Errorf("%s was refused for %q rather than for being undeclared", name, decision.Reason)
		}
	}
}

func TestADecisionSaysWhatItWasAbout(t *testing.T) {
	alice, err := policy(t).Grant("alice")
	if err != nil {
		t.Fatalf("grant for alice: %v", err)
	}

	write := authz.Permission{Resource: authz.Rulesets, Action: authz.Write}
	decision := alice.DecideWithin(write, "globex")

	if decision.Permission != write {
		t.Errorf("the decision is about %s", decision.Permission)
	}
	if decision.Tenant != "globex" {
		t.Errorf("the decision names tenant %q", decision.Tenant)
	}
	if decision.Reason != authz.NoPermission {
		t.Errorf("the decision reads %q; lacking the permission outranks the tenant", decision.Reason)
	}
}

func TestAGrantCannotBeEditedByWhoeverHoldsIt(t *testing.T) {
	compiled := policy(t)
	alice, err := compiled.Grant("alice")
	if err != nil {
		t.Fatalf("grant for alice: %v", err)
	}

	alice.Tenants()[0] = "globex"
	alice.Roles()[0] = "operator"
	alice.Permissions()[0] = authz.Permission{Resource: authz.Rulesets, Action: authz.Write}

	if !alice.Within("acme") || alice.Within("globex") {
		t.Errorf("editing the returned tenants changed the grant: %v", alice.Tenants())
	}
	if !slices.Equal(alice.Roles(), []string{"analyst"}) {
		t.Errorf("editing the returned roles changed the grant: %v", alice.Roles())
	}
	if alice.Allows(authz.Permission{Resource: authz.Rulesets, Action: authz.Write}) {
		t.Error("editing the returned permissions changed the grant")
	}

	role, _ := compiled.Role("analyst")
	role.Permissions()[0] = authz.Permission{Resource: authz.Agents, Action: authz.Delete}
	if role.Allows(authz.Permission{Resource: authz.Agents, Action: authz.Delete}) {
		t.Error("editing the returned permissions changed the role")
	}
}
