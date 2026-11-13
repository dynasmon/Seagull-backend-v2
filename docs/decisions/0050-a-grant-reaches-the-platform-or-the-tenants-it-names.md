# 50. A grant reaches the platform or the tenants it names, and what every tenant shares is held only by a grant of the platform

## Context

[ADR 14](0014-a-token-says-who-and-the-policy-says-what.md) gave a binding roles
and tenants and nothing else. `Grant.DecideWithin` decides a permission inside a
tenant; `Grant.Decide` decides it with no tenant, for operations that are not
about a tenant's records. Nothing said which grants may hold the second kind, so
a binding to one tenant that carried such a permission held it over the
platform.

The integration audit of 2026-11-09 bound `globex-admin` to `administrator`
with `tenants: [globex]` and, with it:

- listed the eight sessions of `dev-admin`, an administrator of `default`, and
  ended one, whose token then answered `401 session_revoked`;
- published a ruleset and activated it; `analysis-engine` pinned it, and the
  next detections of an agent of `default` carried its identifier and the
  severity it had changed. A ruleset is the platform's
  ([ADR 15](0015-a-ruleset-is-published-to-a-log.md)), so one with no useful
  rule blinds every tenant the same way;
- published update packages, under `agents:write`, the permission that
  registers an agent within a tenant, although a root, a catalog and a package
  are held for the whole platform
  ([ADR 31](0031-an-agent-release-is-authorized-off-the-platform.md)).

Agents, alerts, incidents, policies, assignments and rollouts held: another
tenant's identifier answered as one that does not exist. An analyst of `globex`
was refused both session routes, so permissions decided correctly. What was
missing is scope. The development policy describes `administrator` as
administering the platform itself, so the file read as it was meant: the defect
is that an administrator of one tenant could not be written, and that nothing
warned when one was attempted (BE-098).

## Decision

**A permission is the platform's or a tenant's, and one table says which.**
`internal/authz/scope.go` states it for every resource and action:

| Resource | `read` | `write` | `delete` |
|---|---|---|---|
| `events`, `detections`, `alerts`, `incidents`, `agents` | tenant | tenant | tenant |
| `rulesets` | tenant | platform | platform |
| `policies`, `sessions`, `releases` | platform | platform | platform |

The platform's is what every tenant shares: what detects, who is signed in, who
may do what, and what an agent may install. A permission the table does not
hold has no scope and is not a permission, so `Permission.Valid` refuses it
wherever an undeclared one is refused, and a test fails when a resource or an
action is added without a line here.

**A binding says what it reaches.** `scope: platform` or `scope: tenant`, on
every binding. Nothing is inferred: a binding that states no scope is refused
where it is read, and is not taken for one of a tenant. A binding of `tenant`
lists at least one. A binding of `platform` holds the platform permissions of
its roles, and their tenant permissions inside the tenants it lists and nowhere
else; it may list none, `tenants: []`, and then reaches no tenant's records at
all. An empty list is still never a wildcard, and the platform is never every
tenant.

**A binding of `tenant` that carries a platform permission is refused when the
policy is compiled.** `authz.Compile` names the subject, the role and the
permission, and whatever reads a policy refuses it alike: `control-api` and
`query-api` read the same file through `internal/policyfile` and neither
starts. The grant is not narrowed instead. A process that says why it will not
start is better than a grant that silently means less than its file says.

**A decision takes the path that matches.** `Grant.Decide` answers for a
platform permission only to a grant of the platform, and refuses any other with
`out_of_scope`. No compiled policy produces such a grant; the check stays
because `Decide` is where every route asks. A tenant's record is decided by
`Grant.DecideWithin`, naming the tenant, and acting on an alert or an incident
somebody else holds is now decided inside the tenant of that record.
`rulesets:read` is a tenant's permission with no tenant to name: a ruleset is
the platform's, reading it changes nothing, and whoever works a tenant's
detections reads the rule that made them. Its routes ask only that the caller
hold it.

**Publishing a release takes a permission of its own, `releases:write`.** An
update root, a catalog and a package are published under it. `agents:write`
stays a tenant's: registering an agent, binding its identity, publishing its
policy, assigning it a release and running a rollout are all decided inside the
tenant.

**The sessions of another subject are the platform's.** Listing them is
`sessions:read` and ending one `sessions:delete`. A caller lists and ends its
own with no permission at all. A grant of a tenant may not end the sessions of
a subject bound only inside its tenants: a session stands in for a subject, not
for a subject in a tenant, and whether a subject is bound nowhere else is a fact
of the policy at one moment, which BE-078 makes change under a running process.

**A caller is shown what its grant reaches.** A session describes its grant in
`seagull.control.v1.Grant`, which carries the scope beside the tenants,
`SCOPE_PLATFORM` or `SCOPE_TENANT`, and names `releases` among the resources of
a permission. A client that draws its controls from the grant draws the line
the server decides by. It is told and decides nothing: every route still asks
`Decide` or `DecideWithin`. `control.Unnamed`, what is decided and cannot be
shown, holds nothing.

**The document keeps `schema_version: 1`.** No installation holds a file of the
earlier layout, and one that did is refused at the binding that states no
scope, which says more than a version would.

## What this deliberately does not do

**No ruleset of a tenant's own.** What detects is one ruleset for the platform;
a tenant's tuning is BE-084's document.

**No role that differs by tenant.** A subject has one binding, and its roles
apply in every tenant it lists.

**No live policy.** The file is read when a process starts. BE-078 carries the
same model onto its log, and compiles through the same `authz.Compile`.

## Consequences

- [ADR 14](0014-a-token-says-who-and-the-policy-says-what.md) is amended: a
  binding carries roles, a scope and tenants, and only a binding of `tenant`
  must list one.
- [ADR 15](0015-a-ruleset-is-published-to-a-log.md) and
  [ADR 31](0031-an-agent-release-is-authorized-off-the-platform.md) are amended
  to say who may publish: a grant of the platform, holding `rulesets:write` for
  a ruleset and `releases:write` for a root, a catalog or a package.
- [ADR 47](0047-the-query-plane-decides-by-the-policy-and-a-certificate-organisation-authorises-nothing.md)
  follows: the query plane refuses the file the control plane refuses, and a
  grant of the platform that lists no tenant hunts nowhere, `403 unscoped`.
- A role that mixes platform and tenant permissions binds only at the platform.
  `deploy/policy.yml` therefore declares two administrators,
  `administrator` and `tenant-administrator`, and the development PKI issues an
  identity for each.
- Every policy identifier changes once, because what a binding reaches is part
  of what a policy is.
- `seagull_control_authorizations_total` may carry the reason `out_of_scope`.
  Seen once, it means a grant reached a route by something other than a
  compiled policy.
- An installation writes the scope from its first version (BE-086).
- Contracts `v0.23.0` declare the scope of a grant and the `releases` resource;
  the backend moves to it. What an agent is served does not change.
