package policyfile

import (
	"fmt"
	"io/fs"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
)

const (
	MaxBytes    = 1 << 20
	MaxRoles    = 64
	MaxBindings = 4096
)

// Nothing is returned unless all of it is good: half a policy is an
// authorisation surface nobody wrote, and the missing half is the half that
// refuses.
func Read(source string, data []byte) (*authz.Policy, error) {
	if len(data) > MaxBytes {
		return nil, &Fault{Source: source, Reason: fmt.Sprintf("is %d bytes, above the ceiling of %d", len(data), MaxBytes)}
	}

	r := &reader{source: source}

	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, r.fault(nil, "", "is not readable as YAML: "+err.Error())
	}
	if len(document.Content) == 0 {
		return nil, r.fault(nil, "", "is empty")
	}

	held, refused := fieldsOf(document.Content[0])
	if refused != "" {
		return nil, r.fault(document.Content[0], "", "a policy "+refused)
	}

	if err := r.version(&held); err != nil {
		return nil, err
	}
	roles, err := r.roles(&held)
	if err != nil {
		return nil, err
	}
	bindings, err := r.bindings(&held)
	if err != nil {
		return nil, err
	}
	if left := held.unread(); len(left) > 0 {
		return nil, r.fault(held.at(left[0]), left[0], "is not part of a policy")
	}

	policy, err := authz.Compile(roles, bindings)
	if err != nil {
		return nil, r.refused(held.node, "", err)
	}
	return policy, nil
}

func Policy(fsys fs.FS, name string) (*authz.Policy, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	return Read(name, data)
}

func (r *reader) version(held *mapping) error {
	node, given := held.take("schema_version")
	if !given {
		return r.fault(held.node, "schema_version", "is missing; a document that does not say how it is laid out cannot be read")
	}

	var version int
	if err := node.Decode(&version); err != nil {
		return r.fault(node, "schema_version", "is not a number")
	}
	if version != SchemaVersion {
		return r.fault(node, "schema_version", fmt.Sprintf("is %d and this build reads %d", version, SchemaVersion))
	}
	return nil
}

func (r *reader) roles(held *mapping) ([]authz.Role, error) {
	node, given := held.take("roles")
	if !given {
		return nil, r.fault(held.node, "roles", "is missing; a policy that declares no role can bind nothing")
	}
	node = resolve(node)
	if node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, "roles", "is not a list of roles")
	}
	if len(node.Content) > MaxRoles {
		return nil, r.fault(node, "roles", fmt.Sprintf("holds %d roles, above the ceiling of %d", len(node.Content), MaxRoles))
	}

	roles := make([]authz.Role, 0, len(node.Content))
	for index, item := range node.Content {
		part := fmt.Sprintf("roles[%d]", index)

		fields, refused := fieldsOf(item)
		if refused != "" {
			return nil, r.fault(item, part, "a role "+refused)
		}

		name, err := r.scalar(&fields, part, "name")
		if err != nil {
			return nil, err
		}
		description, err := r.scalar(&fields, part, "description")
		if err != nil {
			return nil, err
		}

		granted, given := fields.take("permissions")
		if !given {
			return nil, r.fault(fields.at("permissions"), part+".permissions", "is missing")
		}
		written, err := r.strings(granted, part+".permissions")
		if err != nil {
			return nil, err
		}

		permissions := make([]authz.Permission, 0, len(written))
		for at, one := range written {
			permission, err := authz.ParsePermission(one)
			if err != nil {
				return nil, r.refused(granted.Content[at], fmt.Sprintf("%s.permissions[%d]", part, at), err)
			}
			permissions = append(permissions, permission)
		}

		if left := fields.unread(); len(left) > 0 {
			return nil, r.fault(fields.at(left[0]), part+"."+left[0], "is not part of a role")
		}

		role, err := authz.NewRole(name, description, permissions)
		if err != nil {
			return nil, r.refused(item, part, err)
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (r *reader) bindings(held *mapping) ([]authz.Binding, error) {
	node, given := held.take("bindings")
	if !given {
		return nil, r.fault(held.node, "bindings", "is missing; a policy that binds nobody lets nobody in")
	}
	node = resolve(node)
	if node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, "bindings", "is not a list of bindings")
	}
	if len(node.Content) > MaxBindings {
		return nil, r.fault(node, "bindings", fmt.Sprintf("holds %d bindings, above the ceiling of %d", len(node.Content), MaxBindings))
	}

	bindings := make([]authz.Binding, 0, len(node.Content))
	for index, item := range node.Content {
		part := fmt.Sprintf("bindings[%d]", index)

		fields, refused := fieldsOf(item)
		if refused != "" {
			return nil, r.fault(item, part, "a binding "+refused)
		}

		subject, err := r.scalar(&fields, part, "subject")
		if err != nil {
			return nil, err
		}

		roles, err := r.list(&fields, part, "roles")
		if err != nil {
			return nil, err
		}
		tenants, err := r.list(&fields, part, "tenants")
		if err != nil {
			return nil, err
		}

		if left := fields.unread(); len(left) > 0 {
			return nil, r.fault(fields.at(left[0]), part+"."+left[0], "is not part of a binding")
		}

		binding, err := authz.NewBinding(subject, roles, tenants)
		if err != nil {
			return nil, r.refused(item, part, err)
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func (r *reader) list(fields *mapping, part, name string) ([]string, error) {
	node, given := fields.take(name)
	if !given {
		return nil, r.fault(fields.at(name), part+"."+name, "is missing")
	}
	return r.strings(node, part+"."+name)
}

func Written(policy *authz.Policy) string {
	var written strings.Builder
	fmt.Fprintf(&written, "policy %s: %d roles, %d bindings\n", policy.ID(), policy.Roles(), policy.Bindings())
	for _, subject := range policy.Subjects() {
		grant, err := policy.Grant(subject)
		if err != nil {
			continue
		}
		fmt.Fprintf(&written, "  %s: %s within %s\n",
			subject, strings.Join(grant.Roles(), ", "), strings.Join(grant.Tenants(), ", "))
	}
	return written.String()
}
