package authz_test

import (
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
)

func TestEveryDeclaredPermissionSurvivesBeingWrittenDown(t *testing.T) {
	for _, resource := range authz.Resources() {
		for _, action := range authz.Actions() {
			permission := authz.Permission{Resource: resource, Action: action}
			if !permission.Valid() {
				t.Fatalf("%s is declared and not valid", permission)
			}

			read, err := authz.ParsePermission(permission.String())
			if err != nil {
				t.Fatalf("read %q back: %v", permission, err)
			}
			if read != permission {
				t.Errorf("%q read back as %q", permission, read)
			}
		}
	}
}

func TestAPermissionNobodyDeclaredIsRefused(t *testing.T) {
	for name, written := range map[string]string{
		"no separator":        "rulesets",
		"an unknown resource": "secrets:read",
		"an unknown action":   "rulesets:approve",
		"an empty resource":   ":read",
		"an empty action":     "rulesets:",
		"a plural verb":       "rulesets:reads",
		"the wrong order":     "read:rulesets",
		"nothing at all":      "",
	} {
		if _, err := authz.ParsePermission(written); err == nil {
			t.Errorf("%s (%q) was accepted", name, written)
		}
	}
}

func TestARefusedPermissionSaysWhatThereIsInstead(t *testing.T) {
	_, err := authz.ParsePermission("secrets:read")
	if err == nil {
		t.Fatal("an unknown resource was accepted")
	}
	for _, resource := range authz.Resources() {
		if !strings.Contains(err.Error(), resource.String()) {
			t.Errorf("the refusal %q does not mention %q", err, resource)
		}
	}
}

func TestAZeroPermissionIsNotAPermission(t *testing.T) {
	if (authz.Permission{}).Valid() {
		t.Error("the zero permission reports itself valid")
	}
}
