package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/policyfile"
)

func shipped(t *testing.T) *authz.Policy {
	t.Helper()

	policy, err := policyfile.Policy(os.DirFS(filepath.Join("..", "..", "deploy")), "policy.yml")
	if err != nil {
		t.Fatalf("read the shipped policy: %v", err)
	}
	return policy
}

func TestTheShippedPolicyLoads(t *testing.T) {
	policy := shipped(t)

	if policy.Bindings() == 0 || policy.Roles() == 0 {
		t.Fatalf("the shipped policy holds %d roles and %d bindings", policy.Roles(), policy.Bindings())
	}
	if !slices.Equal(policy.Subjects(), []string{"dev-admin", "dev-analyst"}) {
		t.Errorf("the shipped policy binds %v", policy.Subjects())
	}
}

// The identities the development PKI issues have to be the ones the shipped
// policy binds, or make up brings a stack nobody can use.
func TestTheShippedPolicyBindsTheIdentitiesTheDevelopmentPKIIssues(t *testing.T) {
	policy := shipped(t)

	for subject, expected := range map[string][]string{
		"dev-analyst": {"analyst"},
		"dev-admin":   {"administrator"},
	} {
		grant, err := policy.Grant(subject)
		if err != nil {
			t.Errorf("the development PKI issues %q and the policy binds nothing to it: %v", subject, err)
			continue
		}
		if !slices.Equal(grant.Roles(), expected) {
			t.Errorf("%q holds %v", subject, grant.Roles())
		}
		if !grant.Within("default") {
			t.Errorf("%q covers %v, and the PKI issues tenant \"default\"", subject, grant.Tenants())
		}
	}
}

func TestTheShippedAnalystCannotAdminister(t *testing.T) {
	grant, err := shipped(t).Grant("dev-analyst")
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	for _, permission := range []authz.Permission{
		{Resource: authz.Rulesets, Action: authz.Write},
		{Resource: authz.Agents, Action: authz.Delete},
		{Resource: authz.Sessions, Action: authz.Delete},
		{Resource: authz.Policies, Action: authz.Read},
	} {
		if grant.Allows(permission) {
			t.Errorf("the shipped analyst holds %s", permission)
		}
	}
	if !grant.Allows(authz.Permission{Resource: authz.Events, Action: authz.Read}) {
		t.Error("the shipped analyst cannot read events")
	}
}

// Nothing may hold a permission this build does not declare: the policy is read
// at startup, and a role naming something undeclared stops the process.
func TestEveryPermissionTheShippedPolicyGrantsIsDeclared(t *testing.T) {
	policy := shipped(t)

	for _, subject := range policy.Subjects() {
		grant, err := policy.Grant(subject)
		if err != nil {
			t.Fatalf("grant for %q: %v", subject, err)
		}
		for _, permission := range grant.Permissions() {
			if !permission.Valid() {
				t.Errorf("%q holds %q, which this build does not declare", subject, permission)
			}
		}
	}
}
