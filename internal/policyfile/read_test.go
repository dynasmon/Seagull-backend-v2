package policyfile_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/policyfile"
)

const document = `
schema_version: 1

roles:
  - name: analyst
    description: reads what the platform stored
    permissions:
      - events:read
      - detections:read

  - name: engineer
    description: writes the rules
    permissions:
      - rulesets:read
      - rulesets:write

bindings:
  - subject: dev-analyst
    roles: [analyst]
    tenants: [default]

  - subject: dev-engineer
    roles: [analyst, engineer]
    tenants: [default, acme]
`

// Composed rather than edited by hand, so that a case meant to test one refusal
// cannot quietly become a test of malformed YAML.
func compose(roles, bindings string) string {
	return "schema_version: 1\n\nroles:\n" + roles + "\nbindings:\n" + bindings
}

const (
	goodRole    = "  - name: analyst\n    description: reads what the platform stored\n    permissions:\n      - events:read\n"
	goodBinding = "  - subject: dev-analyst\n    roles: [analyst]\n    tenants: [default]\n"
)

func read(t *testing.T, written string) *authz.Policy {
	t.Helper()
	policy, err := policyfile.Read("policy.yml", []byte(written))
	if err != nil {
		t.Fatalf("read the policy: %v", err)
	}
	return policy
}

func TestAPolicyDocumentBecomesWhatItSays(t *testing.T) {
	policy := read(t, document)

	if policy.Roles() != 2 || policy.Bindings() != 2 {
		t.Fatalf("the document became %d roles and %d bindings", policy.Roles(), policy.Bindings())
	}

	grant, err := policy.Grant("dev-engineer")
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !slices.Equal(grant.Roles(), []string{"analyst", "engineer"}) {
		t.Errorf("the engineer holds %v", grant.Roles())
	}
	if !slices.Equal(grant.Tenants(), []string{"acme", "default"}) {
		t.Errorf("the engineer reads %v", grant.Tenants())
	}
	if !grant.Allows(authz.Permission{Resource: authz.Rulesets, Action: authz.Write}) {
		t.Error("the engineer may not write rulesets")
	}

	analyst, err := policy.Grant("dev-analyst")
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if analyst.Allows(authz.Permission{Resource: authz.Rulesets, Action: authz.Write}) {
		t.Error("the analyst may write rulesets")
	}
}

func TestTheSameDocumentIsTheSamePolicy(t *testing.T) {
	if first, second := read(t, document), read(t, document); first.ID() != second.ID() {
		t.Errorf("one document became %q and %q", first.ID(), second.ID())
	}
}

// The key that is not there and the key that is misspelled must not be the same
// thing. `tenant:` for `tenants:` reads as "no tenants", and a policy is exactly
// the document where a silent default is a security decision nobody made.
func TestAKeyNobodyAskedAboutIsRefused(t *testing.T) {
	for name, written := range map[string]string{
		"at the top": strings.Replace(document, "roles:\n", "role_definitions:\n  - x\nroles:\n", 1),
		"in a role":  strings.Replace(document, "    description: reads what the platform stored", "    descriptions: reads what the platform stored\n    description: reads", 1),
		"in a binding": strings.Replace(document,
			"    tenants: [default]\n\n  - subject: dev-engineer",
			"    tenants: [default]\n    tenant: default\n\n  - subject: dev-engineer", 1),
	} {
		if _, err := policyfile.Read("policy.yml", []byte(written)); err == nil {
			t.Errorf("a key nobody asked about %s was accepted", name)
		}
	}
}

func TestAHalfWrittenPolicyIsRefused(t *testing.T) {
	for name, written := range map[string]string{
		"no schema version":                         strings.Replace(document, "schema_version: 1", "", 1),
		"a schema version this build does not read": strings.Replace(document, "schema_version: 1", "schema_version: 2", 1),
		"a schema version that is not a number":     strings.Replace(document, "schema_version: 1", "schema_version: one", 1),
		"no roles":                                  "schema_version: 1\n\nbindings:\n" + goodBinding,
		"no bindings":                               document[:strings.Index(document, "bindings:")],
		"a role with no name":                       strings.Replace(document, "  - name: analyst\n", "  - x: analyst\n", 1),
		"a role with no description": strings.Replace(document,
			"    description: reads what the platform stored\n", "", 1),
		"a role with no permissions": strings.Replace(document,
			"    permissions:\n      - events:read\n      - detections:read\n", "", 1),
		"a binding with no subject": strings.Replace(document, "  - subject: dev-analyst\n", "  - x: dev-analyst\n", 1),
		"a binding with no roles":   strings.Replace(document, "    roles: [analyst]\n", "", 1),
		"a binding with no tenants": strings.Replace(document, "    tenants: [default]\n\n", "\n", 1),
		"nothing at all":            "",
		"not a mapping":             "- a\n- b\n",
		"not YAML":                  "schema_version: 1\n  roles: [\n",
	} {
		if _, err := policyfile.Read("policy.yml", []byte(written)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestAListWrittenAsAValueIsRefused(t *testing.T) {
	for name, written := range map[string]string{
		"roles":   compose(goodRole, "  - subject: dev-analyst\n    roles: analyst\n    tenants: [default]\n"),
		"tenants": compose(goodRole, "  - subject: dev-analyst\n    roles: [analyst]\n    tenants: default\n"),
		"permissions": compose(
			"  - name: analyst\n    description: reads\n    permissions: events:read\n", goodBinding),
	} {
		_, err := policyfile.Read("policy.yml", []byte(written))
		if err == nil {
			t.Errorf("%s written as a value was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "is not a list") {
			t.Errorf("%s was refused for %q rather than for not being a list", name, err)
		}
	}
}

func TestAFaultSaysWhereInTheFileToLook(t *testing.T) {
	written := strings.Replace(document, "      - events:read", "      - secrets:read", 1)

	_, err := policyfile.Read("policy.yml", []byte(written))
	if err == nil {
		t.Fatal("an undeclared resource was accepted")
	}

	var fault *policyfile.Fault
	if !errors.As(err, &fault) {
		t.Fatalf("the refusal is %T and not a fault", err)
	}
	if fault.Source != "policy.yml" {
		t.Errorf("the fault names %q", fault.Source)
	}
	if fault.Line == 0 || fault.Column == 0 {
		t.Errorf("the fault is at %d:%d", fault.Line, fault.Column)
	}
	if !strings.Contains(fault.Part, "permissions") {
		t.Errorf("the fault names part %q", fault.Part)
	}
	if !strings.Contains(err.Error(), "secrets") {
		t.Errorf("the fault %q does not say what was wrong", err)
	}
}

func TestTheDomainsRefusalSurvivesBeingPositioned(t *testing.T) {
	written := strings.Replace(document, "    roles: [analyst]", "    roles: [auditor]", 1)

	_, err := policyfile.Read("policy.yml", []byte(written))
	if err == nil {
		t.Fatal("a binding naming an undeclared role was accepted")
	}

	var fault *policyfile.Fault
	if !errors.As(err, &fault) {
		t.Fatalf("the refusal is %T and not a fault", err)
	}
	if errors.Unwrap(fault) == nil {
		t.Error("the fault carries no cause")
	}
	if !strings.Contains(err.Error(), "auditor") {
		t.Errorf("the fault %q does not name the role", err)
	}
}

func TestADocumentTooLargeToBeAPolicyIsRefused(t *testing.T) {
	oversized := make([]byte, policyfile.MaxBytes+1)
	for index := range oversized {
		oversized[index] = ' '
	}
	if _, err := policyfile.Read("policy.yml", oversized); err == nil {
		t.Error("a document above the ceiling was read")
	}
}

func TestThePolicyIsReadOutOfAFilesystemTheCallerChose(t *testing.T) {
	fsys := fstest.MapFS{"etc/policy.yml": &fstest.MapFile{Data: []byte(document)}}

	policy, err := policyfile.Policy(fsys, "etc/policy.yml")
	if err != nil {
		t.Fatalf("read the policy: %v", err)
	}
	if policy.Bindings() != 2 {
		t.Errorf("the policy holds %d bindings", policy.Bindings())
	}
	if _, err := policyfile.Policy(fsys, "etc/missing.yml"); err == nil {
		t.Error("a policy that is not there was read")
	}
}

func TestWhatWasLoadedCanBeWrittenOut(t *testing.T) {
	written := policyfile.Written(read(t, document))

	for _, want := range []string{"dev-analyst", "dev-engineer", "analyst, engineer", "acme, default"} {
		if !strings.Contains(written, want) {
			t.Errorf("the rendering does not mention %q:\n%s", want, written)
		}
	}
}
