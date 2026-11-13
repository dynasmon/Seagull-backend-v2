package authz

import "testing"

// Compile refuses a binding of one tenant that holds a platform permission, so
// no policy produces this grant. Decide refuses it as well: it is the one place
// every route asks, and it does not rest on how the grant came to be.
func TestAPlatformPermissionIsRefusedToAGrantThatDoesNotReachThePlatform(t *testing.T) {
	publish := Permission{Resource: Rulesets, Action: Write}
	read := Permission{Resource: Events, Action: Read}

	for name, scope := range map[string]Scope{"a tenant grant": Tenant, "a grant of no scope": ""} {
		held := Grant{subject: "mallory", scope: scope, tenants: []string{"globex"}, permissions: []Permission{publish, read}}

		if decision := held.Decide(publish); decision.Allowed() || decision.Reason != OutOfScope {
			t.Errorf("%s holding %s was answered %q", name, publish, decision.Reason)
		}
		if decision := held.DecideWithin(publish, "globex"); decision.Allowed() || decision.Reason != OutOfScope {
			t.Errorf("%s holding %s was answered %q inside its own tenant", name, publish, decision.Reason)
		}
		if held.Allows(publish) {
			t.Errorf("%s is said to be allowed %s", name, publish)
		}
		if decision := held.DecideWithin(read, "globex"); !decision.Allowed() {
			t.Errorf("%s was refused %s in its own tenant: %q", name, read, decision.Reason)
		}
	}

	root := Grant{subject: "root", scope: Platform, permissions: []Permission{publish}}
	if decision := root.Decide(publish); !decision.Allowed() {
		t.Errorf("a grant of the platform was refused %s: %q", publish, decision.Reason)
	}
}

// The table is the only place a permission gets its scope. Taking a line out of
// it is what forgetting to write one looks like, and what is left is refused
// everywhere an undeclared permission is.
func TestAPermissionTheTableDoesNotHoldIsNotAPermission(t *testing.T) {
	held := reach[Policies]
	delete(reach, Policies)
	t.Cleanup(func() { reach[Policies] = held })

	rewrite := Permission{Resource: Policies, Action: Write}
	if rewrite.Valid() || rewrite.Scope().Valid() {
		t.Fatalf("%s is declared with no scope and reports itself a permission of %q", rewrite, rewrite.Scope())
	}
	if _, err := NewRole("keeper", "rewrites the policy", []Permission{rewrite}); err == nil {
		t.Error("a role was built from a permission with no scope")
	}
	root := Grant{subject: "root", permissions: []Permission{rewrite}}
	if decision := root.Decide(rewrite); decision.Reason != Undeclared {
		t.Errorf("a permission with no scope was decided %q", decision.Reason)
	}
}
