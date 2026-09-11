# 24. An agent is registered by the control plane, and the gateway is told when to stop honouring it

> Amended by [ADR 26](0026-an-agent-sends-into-the-tenant-it-was-registered-in.md).
> An agent the roster has never heard of is no longer admitted: the roster now
> also says which tenant an agent's telemetry belongs to, and an agent the
> registry never named has none. Registering still takes nothing away.

## Context

[ADR 2](0002-identity-comes-from-the-certificate.md) settled where an agent's
identity comes from: the verified client certificate, read by the gateway that
terminated the TLS handshake. It also settled what must never happen on that
path — no proxy header, no request-body claim, no credential row read per batch,
no permissive fallback. v1 had all four, and its `X-Agent-Cert-CN` header with a
`warn` default meant anything that could reach the backend could claim to be any
agent.

That answers *who is talking*. It does not answer *whether the platform still
wants to listen*, and until now nothing did. A certificate signed by the agent
authority was admitted for as long as it was valid, and there was no way to stop
one: no revocation list is checked, and `notes/v1-lessons.md` has carried
"certificate revocation is not checked; short lifetimes are the current answer"
since the gateway was built.

BE-031 asks for the missing half — an agent registry that is the source of truth
for an agent's administrative lifecycle, with enrollment separated from
ingestion, auditable lifecycle changes, and one constraint written twice:

> Gateway continua capaz de autenticar o hot path sem lookup remoto por
> evento/batch.
>
> Não transformar agent registry em dependência sincrônica obrigatória para cada
> evento.

v1 shows exactly why that constraint is there. Its agent authentication wrote to
a hot row on every request and consumed a use counter that eventually exhausted
itself in normal operation: an availability failure caused by putting a
control-plane store on a data-plane path.

## Decision

**The registry records what was decided about an agent. The certificate still
says who it is. What the gateway learns is when to stop honouring an identity,
and it learns it from the backbone.**

Four parts.

### An agent is registered, and registering it takes nothing away

`internal/agent` states what an agent is administratively: an identifier, the
tenant it belongs to, what the machine says it is, the certificate identity bound
to it, and a state. Registration is an operator act guarded by `agents:write`
**in the tenant being registered into** — an agent cannot choose its own tenant,
which is what BE-033 will build on.

A registered agent starts `pending` and is admitted, exactly as an unregistered
one is. This is deliberate: if registering an agent made it *less* able to send
than never registering it, the incentive would be to skip the registry. The
registry adds the ability to stop, and nothing else.

### Becoming active is a consequence of being given something to authenticate with

`pending → active` is not in the state machine. An agent becomes active by
having a certificate identity **bound** to it — subject, serial, SHA-256
fingerprint, validity — and the binding is refused unless the subject is this
agent's own identifier, so a certificate issued to somebody else cannot be
recorded against it. One certificate belongs to one agent: the fingerprint is
unique across the registry, because a fingerprint shared by two agents is a
revocation nobody can act on.

Today an operator performs the binding with the certificate that was issued out
of band. **BE-032 replaces the operator with the certificate authority**, which
binds what it just signed; that is the seam, and it is why the record is a
statement by the issuer rather than something derived here.

### The three endings are three different facts, and two of them are final

```text
pending  → disabled, revoked, decommissioned
active   → disabled, revoked, decommissioned
disabled → active, revoked, decommissioned
revoked, decommissioned → nowhere
```

`disabled` is reversible and says an operator stopped listening to a machine that
is still trusted. `revoked` says the credential is not to be trusted.
`decommissioned` says the machine is gone. Collapsing them would lose the only
distinction that decides whether a certificate may be issued for the identity
again.

**Revoking and decommissioning are final, and re-enrolment means a new
identifier.** The data plane knows an agent by its identifier alone, so an
identifier that came back would re-admit the certificate that was revoked
alongside whichever one replaced it. Every lifecycle change carries a reason and
an actor, and the trail is append-only, one row per revision.

### What the gateway holds is a roster, and it arrives on the backbone

The registry lives in PostgreSQL beside alerts and incidents — the relational,
person-owned, strongly consistent workload [ADR 12](0012-storage-is-owned-per-workload.md)
named it for, and the migrator that applies that schema is now `control-migrator`
rather than `alert-migrator`, because it applies three tables and only one of
them is about alerts.

The gateway never reads it. `security.agents` is a compacted topic keyed by the
agent, carrying `seagull.agent.v1.Admission` — an agent, a tenant, a state and
the revision it was decided at. The gateway replays the topic before it serves
and follows it afterwards, exactly as the control plane follows
`security.rulesets` ([ADR 15](0015-a-ruleset-is-published-to-a-log.md)), and
holds the answer in memory. Refusing a batch costs a map lookup.

An agent the roster has never heard of is admitted, because the certificate
already decided that it is an agent. Under BE-032 that stops being reachable
from outside: a certificate is issued only against a registration, so "holds a
certificate" will imply "was registered". The roster's job is the other
direction.

The record the data plane receives is deliberately less than the record the
registry holds: no reason, no operator, no certificate. A data-plane process
learns that an identity is no longer honoured, not who stopped honouring it.

**Nothing is evicted from the roster.** Evicting a refusal would re-admit a
revoked agent, so the ceiling is the number of registered agents — a number the
platform chooses, not one a caller can drive. A record older than the one already
applied is stepped over, so two control planes publishing about the same agent at
once cannot leave a gateway holding the earlier answer for ever.

### The registry is written first, and what the log was not told is outstanding

A decision is recorded in PostgreSQL and then published. A crash between the two
leaves an agent whose decision has not reached the gateway — never a gateway
acting on a decision that was never recorded.

That gap is not left to chance. Every row carries `published_revision`, and a row
where it trails `revision` is a decision the data plane has not heard.
`control.Announcer` reads them oldest first, at startup and on every tick, and
publishes them again; one it cannot carry stops the sweep rather than being
stepped over, because skipping a record would tell a gateway a later state while
an earlier one is still missing. A revocation recorded while the backbone was
down is carried when it comes back, and the number still waiting is a gauge.

## Liveness is read where the telemetry landed, and is not part of the registry

BE-031 asks for "first seen, last seen" in the model. `registered_at` is a
control-plane fact and is stored. **`last_seen` is not.**

An agent is registered once and sends continuously. Keeping "when did we last
hear from it" beside what was decided would mean writing to a control-plane store
on the ingest path, at whatever rate the estate produces telemetry — which is v1's
exhausted use counter with a different name, and the thing this card's own "não
fazer" forbids. It would also be a second source of truth about something the
event stream already records exactly.

So the field is on the contract and answered from the analytical store, at the
moment somebody reads an agent, bounded three ways: the agents on the page, the
tenants the caller holds, and a horizon to look back over. It is read from
`ingest_time` — the platform's clock, not the producer's — so an agent cannot
backdate itself alive. A telemetry store that cannot be reached costs the caller
that column and not the answer.

## Consequences

- **The revocation gap is closed without a CRL, an OCSP responder, or a lookup
  per batch.** It is one compacted topic and a map. Short certificate lifetimes
  remain the answer for a *stolen* key whose agent nobody has revoked yet; this
  is the answer for one somebody has.
- **`cmd/ingest-gateway` gains a second backbone client and a startup
  dependency on `security.agents`.** It already verifies the topic it publishes
  to, so the class of dependency is not new; the failure mode is that a gateway
  which cannot read the roster does not serve, which is the fail-closed direction.
- **`cmd/control-api` gains a read connection to the analytical store**, used for
  one aggregate and nothing else. It writes nothing there, and the query plane
  remains the place a person asks questions of telemetry.
- **The ingest capability may not name the registry.** `tests/architecture`
  refuses `internal/ingest` importing `internal/agent` or `internal/postgres`:
  admissibility reaches the gateway as an answer, and an ingest path that could
  reach the registry would be an ingest path that reads a store per batch.
- **`cmd/alert-migrator` is now `cmd/control-migrator`**, and the compose service
  with it. The `SEAGULL_ALERT_STORE_*` settings keep their names, so a deployment
  changes one service name and no environment variable.
- **BE-032 has a place to attach.** Issuance binds the identity it just signed;
  renewal rebinds without moving the agent; revoking a certificate is revoking
  the agent, which already has an effect. CA rotation is untouched by this record.
- **BE-033 has a trustworthy source.** The tenant an agent belongs to is now
  recorded against it and already travels to the data plane on the admission
  record. Stamping it onto events instead of the gateway-wide tenant is a change
  to the gateway's roster lookup, not a new mechanism.
- **BE-034 has the shape of the projection it needs.** What is observed of an
  endpoint — its platform, its address, when it was last heard from — is read from
  the stream rather than written into the registry, and this record is why.
