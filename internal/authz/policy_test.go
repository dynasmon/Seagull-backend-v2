package authz_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
)

func permissions(t *testing.T, written ...string) []authz.Permission {
	t.Helper()
	held := make([]authz.Permission, 0, len(written))
	for _, one := range written {
		permission, err := authz.ParsePermission(one)
		if err != nil {
			t.Fatalf("read %q: %v", one, err)
		}
		held = append(held, permission)
	}
	return held
}

func role(t *testing.T, name string, written ...string) authz.Role {
	t.Helper()
	built, err := authz.NewRole(name, "what "+name+" is for", permissions(t, written...))
	if err != nil {
		t.Fatalf("build role %q: %v", name, err)
	}
	return built
}

func binding(t *testing.T, subject string, roles, tenants []string) authz.Binding {
	t.Helper()
	built, err := authz.NewBinding(subject, roles, tenants)
	if err != nil {
		t.Fatalf("bind %q: %v", subject, err)
	}
	return built
}

func policy(t *testing.T) *authz.Policy {
	t.Helper()
	compiled, err := authz.Compile(
		[]authz.Role{
			role(t, "analyst", "events:read", "detections:read"),
			role(t, "operator", "rulesets:read", "rulesets:write"),
		},
		[]authz.Binding{
			binding(t, "alice", []string{"analyst"}, []string{"acme"}),
			binding(t, "bob", []string{"analyst", "operator"}, []string{"acme", "globex"}),
		},
	)
	if err != nil {
		t.Fatalf("compile the policy: %v", err)
	}
	return compiled
}

// A binding that names a role nobody declared is the failure this whole shape
// exists to refuse: compared as strings it silently grants nothing, and reads in
// the document exactly like a binding that grants something.
func TestABindingCannotNameARoleNobodyDeclared(t *testing.T) {
	_, err := authz.Compile(
		[]authz.Role{role(t, "analyst", "events:read")},
		[]authz.Binding{binding(t, "alice", []string{"analyst", "auditor"}, []string{"acme"})},
	)
	if err == nil {
		t.Fatal("a binding naming an undeclared role compiled")
	}
	for _, want := range []string{"alice", "auditor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not name %q", err, want)
		}
	}
}

func TestAPolicyRefusesWhatItCannotHoldToOneReading(t *testing.T) {
	analyst := role(t, "analyst", "events:read")

	for name, build := range map[string]func() error{
		"a role declared twice": func() error {
			_, err := authz.Compile(
				[]authz.Role{analyst, role(t, "analyst", "events:read", "detections:read")},
				[]authz.Binding{binding(t, "alice", []string{"analyst"}, []string{"acme"})},
			)
			return err
		},
		"a subject bound twice": func() error {
			_, err := authz.Compile([]authz.Role{analyst}, []authz.Binding{
				binding(t, "alice", []string{"analyst"}, []string{"acme"}),
				binding(t, "alice", []string{"analyst"}, []string{"globex"}),
			})
			return err
		},
		"a policy binding nobody": func() error {
			_, err := authz.Compile([]authz.Role{analyst}, nil)
			return err
		},
		"an unconstructed role": func() error {
			_, err := authz.Compile([]authz.Role{{}}, []authz.Binding{binding(t, "alice", []string{"analyst"}, []string{"acme"})})
			return err
		},
		"an unconstructed binding": func() error {
			_, err := authz.Compile([]authz.Role{analyst}, []authz.Binding{{}})
			return err
		},
	} {
		if err := build(); err == nil {
			t.Errorf("%s compiled", name)
		}
	}
}

func TestNeitherHalfOfABindingDefaultsToEverything(t *testing.T) {
	for name, build := range map[string]func() (authz.Binding, error){
		"no roles":   func() (authz.Binding, error) { return authz.NewBinding("alice", nil, []string{"acme"}) },
		"no tenants": func() (authz.Binding, error) { return authz.NewBinding("alice", []string{"analyst"}, nil) },
		"neither":    func() (authz.Binding, error) { return authz.NewBinding("alice", nil, nil) },
		"no subject": func() (authz.Binding, error) { return authz.NewBinding("", []string{"analyst"}, []string{"acme"}) },
		"a bad tenant": func() (authz.Binding, error) {
			return authz.NewBinding("alice", []string{"analyst"}, []string{"acme corp"})
		},
		"a bad role": func() (authz.Binding, error) { return authz.NewBinding("alice", []string{"Analyst"}, []string{"acme"}) },
		"a bad subject": func() (authz.Binding, error) {
			return authz.NewBinding("alice smith", []string{"analyst"}, []string{"acme"})
		},
	} {
		if _, err := build(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestARoleMustAllowSomethingAndSayWhatItIsFor(t *testing.T) {
	for name, build := range map[string]func() (authz.Role, error){
		"no permissions": func() (authz.Role, error) { return authz.NewRole("analyst", "reads", nil) },
		"no description": func() (authz.Role, error) {
			return authz.NewRole("analyst", "", permissions(t, "events:read"))
		},
		"no name": func() (authz.Role, error) { return authz.NewRole("", "reads", permissions(t, "events:read")) },
		"an undeclared permission": func() (authz.Role, error) {
			return authz.NewRole("analyst", "reads", []authz.Permission{{Resource: "secrets", Action: "read"}})
		},
	} {
		if _, err := build(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestAPolicyIsNamedByWhatIsInIt(t *testing.T) {
	first, second := policy(t), policy(t)
	if first.ID() != second.ID() {
		t.Fatalf("the same policy is named %q and %q", first.ID(), second.ID())
	}
	if first.ID() == "" {
		t.Fatal("the policy has no identity")
	}

	for name, build := range map[string]func() (*authz.Policy, error){
		"a widened role": func() (*authz.Policy, error) {
			return authz.Compile(
				[]authz.Role{role(t, "analyst", "events:read", "detections:read", "alerts:read"), role(t, "operator", "rulesets:read", "rulesets:write")},
				[]authz.Binding{
					binding(t, "alice", []string{"analyst"}, []string{"acme"}),
					binding(t, "bob", []string{"analyst", "operator"}, []string{"acme", "globex"}),
				})
		},
		"a widened binding": func() (*authz.Policy, error) {
			return authz.Compile(
				[]authz.Role{role(t, "analyst", "events:read", "detections:read"), role(t, "operator", "rulesets:read", "rulesets:write")},
				[]authz.Binding{
					binding(t, "alice", []string{"analyst"}, []string{"acme", "globex"}),
					binding(t, "bob", []string{"analyst", "operator"}, []string{"acme", "globex"}),
				})
		},
		"a renamed role": func() (*authz.Policy, error) {
			return authz.Compile(
				[]authz.Role{role(t, "analyst", "events:read", "detections:read"), role(t, "responder", "rulesets:read", "rulesets:write")},
				[]authz.Binding{
					binding(t, "alice", []string{"analyst"}, []string{"acme"}),
					binding(t, "bob", []string{"analyst", "responder"}, []string{"acme", "globex"}),
				})
		},
	} {
		changed, err := build()
		if err != nil {
			t.Fatalf("%s: compile: %v", name, err)
		}
		if changed.ID() == first.ID() {
			t.Errorf("%s did not change the policy identity", name)
		}
	}
}

func TestOrderDoesNotChangeWhatAPolicyIs(t *testing.T) {
	roles := []authz.Role{role(t, "analyst", "events:read", "detections:read"), role(t, "operator", "rulesets:read", "rulesets:write")}
	bindings := []authz.Binding{
		binding(t, "alice", []string{"analyst"}, []string{"acme"}),
		binding(t, "bob", []string{"operator", "analyst"}, []string{"globex", "acme"}),
	}

	forwards, err := authz.Compile(roles, bindings)
	if err != nil {
		t.Fatalf("compile forwards: %v", err)
	}
	backwards, err := authz.Compile(
		[]authz.Role{roles[1], roles[0]},
		[]authz.Binding{bindings[1], bindings[0]},
	)
	if err != nil {
		t.Fatalf("compile backwards: %v", err)
	}
	if forwards.ID() != backwards.ID() {
		t.Errorf("reordering renamed the policy: %q against %q", forwards.ID(), backwards.ID())
	}
}

func TestAPolicyReportsWhatItCovers(t *testing.T) {
	compiled := policy(t)
	if subjects := compiled.Subjects(); !slices.Equal(subjects, []string{"alice", "bob"}) {
		t.Errorf("the policy covers %v", subjects)
	}
	if compiled.Roles() != 2 || compiled.Bindings() != 2 {
		t.Errorf("the policy holds %d roles and %d bindings", compiled.Roles(), compiled.Bindings())
	}
	if _, declared := compiled.Role("analyst"); !declared {
		t.Error("the policy does not report a role it declared")
	}
	if _, declared := compiled.Role("auditor"); declared {
		t.Error("the policy reports a role nobody declared")
	}
}
