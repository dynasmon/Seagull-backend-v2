package authz

import "testing"

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
