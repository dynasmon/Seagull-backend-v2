package authz

import "slices"

type Reason string

const (
	Allowed      Reason = "allowed"
	NoGrant      Reason = "no_grant"
	NoPermission Reason = "no_permission"
	OutOfTenant  Reason = "out_of_tenant"
	OutOfScope   Reason = "out_of_scope"
	Undeclared   Reason = "undeclared"
)

type Decision struct {
	Reason     Reason
	Permission Permission
	Tenant     string
}

func (d Decision) Allowed() bool { return d.Reason == Allowed }

// The zero value grants nothing: wherever a grant fails to arrive, what is left
// over refuses instead of permitting.
type Grant struct {
	subject     string
	scope       Scope
	roles       []string
	tenants     []string
	permissions []Permission
}

func (g Grant) Subject() string { return g.subject }

func (g Grant) Scope() Scope { return g.scope }

func (g Grant) Roles() []string { return slices.Clone(g.roles) }

func (g Grant) Tenants() []string { return slices.Clone(g.tenants) }

func (g Grant) Permissions() []Permission { return slices.Clone(g.permissions) }

func (g Grant) Empty() bool { return g.subject == "" }

// Whether the grant holds the permission, and for one of the platform's whether
// the grant reaches the platform. A tenant's permission held is not yet a
// decision about any tenant's records: those go through DecideWithin, so an
// absent tenant can never read as every tenant.
func (g Grant) Decide(permission Permission) Decision {
	decision := Decision{Permission: permission}
	switch {
	case !permission.Valid():
		decision.Reason = Undeclared
	case g.Empty():
		decision.Reason = NoGrant
	case !slices.Contains(g.permissions, permission):
		decision.Reason = NoPermission
	case permission.Scope() == Platform && g.scope != Platform:
		decision.Reason = OutOfScope
	default:
		decision.Reason = Allowed
	}
	return decision
}

func (g Grant) DecideWithin(permission Permission, tenant string) Decision {
	decision := g.Decide(permission)
	decision.Tenant = tenant
	if !decision.Allowed() {
		return decision
	}
	if tenant == "" || !slices.Contains(g.tenants, tenant) {
		decision.Reason = OutOfTenant
	}
	return decision
}

func (g Grant) Allows(permission Permission) bool { return g.Decide(permission).Allowed() }

func (g Grant) Within(tenant string) bool {
	return tenant != "" && slices.Contains(g.tenants, tenant)
}
