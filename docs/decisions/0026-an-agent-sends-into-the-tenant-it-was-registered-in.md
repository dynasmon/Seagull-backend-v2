# 26. An agent sends into the tenant it was registered in, and an agent the registry never named is not admitted

## Context

[ADR 2](0002-identity-comes-from-the-certificate.md) made the gateway overwrite
`origin.agent_id` and `origin.tenant_id` on every event, so a producer chooses
neither. It also left a debt in its consequences: "tenancy is currently a
gateway-wide setting rather than a certificate claim." The setting was
`SEAGULL_TENANT_ID`, and the gateway stamped it on everything it admitted.

A gateway-wide tenant makes one gateway serve exactly one tenant. An estate with
two tenants needs two gateway fleets, and an agent pointed at the wrong one — or
a fleet configured with the wrong value — has its telemetry written into another
estate. Nothing downstream can notice, because everything downstream trusts the
field: detection state is keyed by tenant, an alert's correlation key starts with
it, the stored event and detection carry it, and a hunt is scoped by it. That is
the routing error BE-033 forbids:

> Eventos não atravessam tenant boundary por erro de routing.
>
> Tenant identity é derivada de trust boundary autenticada.

The card names four candidate sources: the certificate identity, the enrollment
identity, a certificate extension and a trusted registry. Two of the ADRs since
ADR 2 already chose between them.
[ADR 24](0024-an-agent-is-registered-by-the-control-plane-and-refused-by-the-gateway.md)
records an agent's tenant at registration — an operator act guarded by
`agents:write` in the tenant being registered into, so an agent never chooses its
own — and carries it to the gateway on `seagull.agent.v1.Admission`.
[ADR 25](0025-the-platform-signs-the-identity-it-binds.md) kept it out of the
certificate, because a tenant in a certificate cannot be corrected without
reissuing one. What was left is the gateway reading it.

ADR 24 also decided something this record has to revisit: "an agent the roster
has never heard of is admitted, because the certificate already decided that it
is an agent." That was sound while the roster answered one question — whether the
platform had stopped honouring an identity. It now answers a second, and for an
agent it has never heard of, the second has no answer.

## Decision

**An agent's tenant is the one the registry recorded it in. It reaches the gateway
on the admission record, the gateway stamps it on every event in place of what
the agent wrote, and an agent the registry never named is not admitted at all.**

### The tenant comes from the registry and from nothing else

The roster a gateway holds keeps, beside the state and the revision it already
kept, the tenant each admission record names. The gateway asks it one question
per batch — which tenant does this agent's telemetry belong to, if the platform
admits it at all — and the answer is a map lookup, exactly as refusing a revoked
agent already was. That tenant is assigned to `origin.tenant_id` on every event of
the batch, replacing whatever the producer put there, which is the assignment
ADR 2 made for the agent identifier applied to the other half of `origin`.

The certificate says who is sending and the registry says whose estate it belongs
to. The two are never merged: the certificate is not read for a tenant, and the
admission record is not read for an identity.

### An agent the registry never named is refused

A certificate the agent authority signed proves an agent exists. It does not say
which estate the agent belongs to, and any tenant the gateway picked for it would
be a guess — the gateway-wide tenant was exactly such a guess, made once for every
agent. So an agent the roster has never heard of is refused with `403` and
`agent_not_registered`, before its body is read, and nothing is published. It is a
different code from `agent_not_admitted` so an operator can tell a missing
registration from a revocation, and like every answer other than `200` it tells
the agent to keep the batch.

ADR 24's reason for admitting unknown agents was an incentive: a registry that
made a registered agent less able to send than an unregistered one would give an
estate a reason to skip it. That still holds — a `pending` agent is admitted —
and it holds more strongly now, because skipping the registry costs an agent
everything.

Two situations reach the refusal, and neither loses telemetry:

- **a certificate signed outside the platform.** Under ADR 25 the platform signs
  only for an agent it registered, so this is `tools/devpki` material or an
  authority an estate shares with something else. It is refused until somebody
  registers the agent, which is the point;
- **a registration the gateway has not read yet.** The control plane publishes the
  admission as it registers the agent, and the gateway follows the log, so the gap
  is the follow latency — or, when the backbone was down, until the announcer
  carries the outstanding decision. The agent's spool closes it.

`SEAGULL_TENANT_ID` is removed rather than kept as a fallback for unregistered
agents. ADR 2 said there is no header, no mode and no fallback; a default tenant
for agents nobody placed would be all three.

### What the roster refuses about a tenant

- **A record naming no tenant, or one the registry could not have written**, is
  malformed, by the same rule registration applies. The reader stops the agent
  it is keyed by, as it does for a state it cannot read, rather than admitting it
  into an empty tenant — which would surface as every batch from that agent
  failing event validation with a `422` that blamed the agent.
- **One revision placing an agent in two tenants** is a conflict, handled like
  one revision deciding both ways: the platform cannot say which it decided, so
  it stops admitting the agent until a later revision says.
- **A later revision decides, tenant included.** No route changes an agent's
  tenant today. If one ever does, the last record wins, because that is the only
  rule on which a gateway that read every record agrees with a gateway that
  started after compaction and read only the last one. Pinning the first tenant a
  gateway saw would make two replicas place the same agent in different estates.

## What this deliberately does not do

**No tenant in the certificate, and no certificate extension.** ADR 25 gave the
reason and it has not changed. A second statement of the tenant would also be a
second place for the two to disagree, and the only safe answer to a disagreement
is refusing the agent, which a registry correction could then never fix without
visiting the machine.

**No integrity protection on the admission record beyond the backbone's.**
Whoever can produce to `security.agents` decides an agent's tenant as well as
whether it is admitted. That is the trust ADR 24 already placed in the log for
revocation, and the answer is the broker ACL BE-004 names — only the control plane
produces to that topic, and gateways only read it — rather than a signature on
each record, which would need a key on every gateway to verify.

**No tenant move.** Nothing reassigns an agent to another tenant, and building it
means deciding what becomes of the detection state, alerts and incidents keyed by
the old one. The roster's rule above is what such a route would inherit.

**No change to the query plane.** `hunt.Scope` still reads the tenants a caller
may see from the caller's certificate; this binds the producer side of the
boundary, and the reader side is the change ADR 14 already describes.

## Consequences

- **One gateway serves every tenant.** A multi-tenant estate stops needing a fleet
  per tenant, and a misrouted agent is placed by its registration, not by the
  gateway it happened to reach.
- **Every agent must be registered before a gateway admits it.** An estate
  upgrading registers its agents first; one that does not sees them refused with
  `agent_not_registered`, their batches kept in their spools, and the refusal
  counter says how many are knocking. There is no such estate yet —
  `Seagull-agent-v2` is empty — and the development agent `tools/devpki` mints is
  registered by `tools/devprobe` before it sends.
- **`ingest.Policy` carries no tenant and `ingest.Roster` answers `Tenant`.** The
  admitter is handed the tenant with the identity, so the capability still names
  neither the registry nor the store, and the architecture rule refusing
  `internal/ingest` the registry holds unchanged.
- **Agent identifiers stay global.** The registry's primary key is the agent, so
  two tenants cannot register one identifier. That is what keeps the event stream's
  partition key — the agent — unambiguous across tenants, and what makes
  "which tenant is this agent in" a question with one answer.
- **Nothing downstream changes.** Every consumer already read `origin.tenant_id`;
  what changed is that the value is now a decision somebody recorded and could be
  asked about, rather than a line of the gateway's configuration.
