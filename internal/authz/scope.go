package authz

// What a permission reaches, and what a binding does. The platform's is what
// every tenant shares, held only by a binding that says the platform; a tenant's
// is held by any binding and acts inside the tenants that binding lists.
// Reaching the platform is never reaching a tenant: its records still need the
// tenant named.
type Scope string

const (
	Platform Scope = "platform"
	Tenant   Scope = "tenant"
)

func (s Scope) Valid() bool { return s == Platform || s == Tenant }

func (s Scope) String() string { return string(s) }

// Said here and nowhere else. A permission missing from this table has no scope
// and is not a permission, so none can be declared without saying whose it is.
var reach = map[Resource]map[Action]Scope{
	Events:     {Read: Tenant, Write: Tenant, Delete: Tenant},
	Detections: {Read: Tenant, Write: Tenant, Delete: Tenant},
	Rulesets:   {Read: Tenant, Write: Platform, Delete: Platform},
	Alerts:     {Read: Tenant, Write: Tenant, Delete: Tenant},
	Incidents:  {Read: Tenant, Write: Tenant, Delete: Tenant},
	Agents:     {Read: Tenant, Write: Tenant, Delete: Tenant},
	Policies:   {Read: Platform, Write: Platform, Delete: Platform},
	Sessions:   {Read: Platform, Write: Platform, Delete: Platform},
	Releases:   {Read: Platform, Write: Platform, Delete: Platform},
}

func (p Permission) Scope() Scope { return reach[p.Resource][p.Action] }
