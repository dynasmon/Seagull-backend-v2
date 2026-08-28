package authz

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
)

var rolePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func ValidRole(name string) bool { return rolePattern.MatchString(name) }

// Nothing is inherited from another role: an inheritance graph is a second
// language to read before anybody can answer what a subject may do.
type Role struct {
	name        string
	description string
	permissions []Permission
}

// A role granting nothing is refused rather than loaded, because it reads in a
// policy document as a grant and behaves as an absence.
func NewRole(name, description string, permissions []Permission) (Role, error) {
	if !ValidRole(name) {
		return Role{}, fmt.Errorf("%q is not a role name: lowercase, digits and dashes, up to 64", name)
	}
	if description == "" {
		return Role{}, fmt.Errorf("role %q says nothing about what it is for", name)
	}
	if len(permissions) == 0 {
		return Role{}, fmt.Errorf("role %q allows nothing; a role that grants nothing should not exist", name)
	}

	kept := make([]Permission, 0, len(permissions))
	for _, permission := range permissions {
		if !permission.Valid() {
			return Role{}, fmt.Errorf("role %q holds %q, which is not a permission", name, permission)
		}
		if !slices.Contains(kept, permission) {
			kept = append(kept, permission)
		}
	}
	sortPermissions(kept)

	return Role{name: name, description: description, permissions: kept}, nil
}

func (r Role) Name() string { return r.name }

func (r Role) Description() string { return r.description }

func (r Role) Permissions() []Permission { return slices.Clone(r.permissions) }

func (r Role) Allows(permission Permission) bool { return slices.Contains(r.permissions, permission) }

var errNoRole = errors.New("no such role")
