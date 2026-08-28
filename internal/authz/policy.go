package authz

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
)

var subjectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)

func ValidSubject(name string) bool { return subjectPattern.MatchString(name) }

// Both halves are required and an empty list is never a wildcard: a role with no
// tenant may act nowhere, and a tenant with no role may do nothing there.
type Binding struct {
	subject string
	roles   []string
	tenants []string
}

func NewBinding(subject string, roles, tenants []string) (Binding, error) {
	if !ValidSubject(subject) {
		return Binding{}, fmt.Errorf("%q is not a subject", subject)
	}

	keptRoles := make([]string, 0, len(roles))
	for _, role := range roles {
		if !ValidRole(role) {
			return Binding{}, fmt.Errorf("subject %q holds %q, which is not a role name", subject, role)
		}
		if !slices.Contains(keptRoles, role) {
			keptRoles = append(keptRoles, role)
		}
	}
	if len(keptRoles) == 0 {
		return Binding{}, fmt.Errorf("subject %q holds no role", subject)
	}

	keptTenants := make([]string, 0, len(tenants))
	for _, tenant := range tenants {
		if !event.ValidIdentifier(tenant) {
			return Binding{}, fmt.Errorf("subject %q is bound to %q, which is not a tenant identifier", subject, tenant)
		}
		if !slices.Contains(keptTenants, tenant) {
			keptTenants = append(keptTenants, tenant)
		}
	}
	if len(keptTenants) == 0 {
		return Binding{}, fmt.Errorf("subject %q is bound to no tenant", subject)
	}

	slices.Sort(keptRoles)
	slices.Sort(keptTenants)
	return Binding{subject: subject, roles: keptRoles, tenants: keptTenants}, nil
}

func (b Binding) Subject() string { return b.subject }

func (b Binding) Roles() []string { return slices.Clone(b.roles) }

func (b Binding) Tenants() []string { return slices.Clone(b.tenants) }

// Immutable once compiled, so a reload landing mid-request cannot widen or
// narrow a decision halfway through making it.
type Policy struct {
	id       ID
	roles    map[string]Role
	bindings map[string]Binding
}

type ID string

func (i ID) String() string { return string(i) }

var (
	ErrUnknownSubject = errors.New("the policy binds no roles to this subject")

	ErrEmptyPolicy = errors.New("a policy with no bindings can allow nothing and is refused rather than loaded")
)

func Compile(roles []Role, bindings []Binding) (*Policy, error) {
	byName := make(map[string]Role, len(roles))
	for _, role := range roles {
		if role.name == "" {
			return nil, errors.New("a policy holds constructed roles and one of them is empty")
		}
		if _, twice := byName[role.name]; twice {
			return nil, fmt.Errorf("role %q is declared twice", role.name)
		}
		byName[role.name] = role
	}

	bySubject := make(map[string]Binding, len(bindings))
	for _, binding := range bindings {
		if binding.subject == "" {
			return nil, errors.New("a policy holds constructed bindings and one of them is empty")
		}
		if _, twice := bySubject[binding.subject]; twice {
			return nil, fmt.Errorf("subject %q is bound twice; one subject has one binding", binding.subject)
		}
		for _, name := range binding.roles {
			if _, declared := byName[name]; !declared {
				return nil, fmt.Errorf("subject %q holds role %q, which %w", binding.subject, name, errNoRole)
			}
		}
		bySubject[binding.subject] = binding
	}

	if len(bySubject) == 0 {
		return nil, ErrEmptyPolicy
	}

	policy := &Policy{roles: byName, bindings: bySubject}
	policy.id = identify(byName, bySubject)
	return policy, nil
}

func (p *Policy) ID() ID { return p.id }

func (p *Policy) Roles() int { return len(p.roles) }

func (p *Policy) Bindings() int { return len(p.bindings) }

func (p *Policy) Subjects() []string { return slices.Sorted(maps.Keys(p.bindings)) }

func (p *Policy) Role(name string) (Role, bool) {
	role, declared := p.roles[name]
	return role, declared
}

// A subject the policy does not mention gets no grant at all, so that nothing
// downstream can read an empty grant as an absence of restriction.
func (p *Policy) Grant(subject string) (Grant, error) {
	binding, bound := p.bindings[subject]
	if !bound {
		return Grant{}, fmt.Errorf("%w: %q", ErrUnknownSubject, subject)
	}

	permissions := make([]Permission, 0, 8)
	for _, name := range binding.roles {
		for _, permission := range p.roles[name].permissions {
			if !slices.Contains(permissions, permission) {
				permissions = append(permissions, permission)
			}
		}
	}
	sortPermissions(permissions)

	return Grant{
		subject:     binding.subject,
		roles:       slices.Clone(binding.roles),
		tenants:     slices.Clone(binding.tenants),
		permissions: permissions,
	}, nil
}

// Every part is written with its length in front, so no two different policies
// can hash alike.
func identify(roles map[string]Role, bindings map[string]Binding) ID {
	digest := sha256.New()

	for _, name := range slices.Sorted(maps.Keys(roles)) {
		role := roles[name]
		write(digest, "role", role.name, role.description)
		for _, permission := range role.permissions {
			write(digest, "permission", permission.String())
		}
	}
	for _, subject := range slices.Sorted(maps.Keys(bindings)) {
		binding := bindings[subject]
		write(digest, "binding", binding.subject)
		for _, role := range binding.roles {
			write(digest, "holds", role)
		}
		for _, tenant := range binding.tenants {
			write(digest, "within", tenant)
		}
	}

	return ID(hex.EncodeToString(digest.Sum(nil))[:32])
}

func write(digest interface{ Write([]byte) (int, error) }, parts ...string) {
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(part))
	}
}
