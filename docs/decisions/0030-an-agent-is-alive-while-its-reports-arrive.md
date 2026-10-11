# 30. An agent's status is a record of its own, and an agent is alive while its reports arrive

## Context

There is no heartbeat. `Agent.last_seen` is read from `security_events`, so it
says when an agent last sent telemetry, and an agent on a host nobody logs into
sends none: it never looks alive however well it runs. The agent keeps a full
account of itself in a local `status.json` that nothing outside its host reads —
whether each of its parts runs, what it holds and has not delivered, its
certificate, the settings and the policy it runs on. BE-053 asks for that account
to reach the platform, for which agents are alive, late or silent to follow from
it, and for none of it to cost a write on the ingest path.

Three things make this different from telemetry. A report describes the agent and
not the host it watches, so it answers a question the registry is asked rather
than one a hunt is. Only the newest report of an agent matters: a fleet's state is
one report per agent, and a report that never arrived is made up for by the next
one, which says everything it does again. And how recently a report arrived is
the platform's to measure: an agent that could report itself alive by writing a
later timestamp would make liveness worthless as a sign that something stopped
one.

## Decision

**A status report is a record of its own — admitted behind the same gate,
published to a compacted topic keyed by the agent, folded by a process of its own
into one row per agent — and an agent's liveness is judged when it is read, from
when the platform received its newest report, against the interval that report
announced.**

### The contract sits beside the registry and is still a record of its own

`seagull.agent.v1.Status` and `StatusBatch` live in the package of the
administrative record, because they are about the same agent and `Agent` now
carries what was observed of it: `liveness`, `last_reported`, and, when one agent
is read, the newest report itself. They are a record of their own all the same,
by [ADR 27](0027-inventory-is-a-record-kind-of-its-own.md)'s method: their own
stream into the gateway, their own topic, their own process and their own table.
A report is never a class of event, so a fleet reporting every minute never makes
the lag of telemetry a function of how many agents there are.

### The gateway admits it behind the same gate

`POST /v1/status` is the third route of the gateway, behind the same verified
certificate, roster answer, rate limiter, capacity bound and body ceiling as
events and inventory, answered with the same `BatchAck` and `Rejection`. The
gateway stamps the agent from the certificate, the tenant from the roster and the
reception from its own clock, exactly as for an event: a copied key cannot speak
for a host in another estate, and an agent the platform stopped admitting is not
heard from on this route either. Everything else a report says — its build, its
privileges, its configuration — is the agent's claim, kept as it said it, and
never an attestation.

### The topic keeps the newest report of every agent

`security.agents.status` is compacted and keyed by the agent. A report stands on
its own, so the newest of each agent is all a reader needs, and a compacted log
keeps it for a reader that starts long after it was written while the reports of
one agent are read in the order they arrived. This is the one record kind whose
topic is the current state rather than a history, and it can be, because nothing
is folded from a report but the report.

### One row per agent, versioned by the platform's clock

`status-projector` folds the topic into ClickHouse `agent_status`, one row per
`(tenant_id, agent_id)`, a `ReplacingMergeTree` versioned by `ingest_time`. The
row carries the report exactly as the gateway published it beside the columns a
fleet is asked about. A replay folds the same rows again, and a report that says
it was written later never stands in for one received after it. It is a failure
domain of its own, so a status store outage costs how fresh liveness is and never
the admission or the storage of telemetry, and the ingest path still writes no
store at all.

### Liveness is judged at read time, and silence decides nothing

`control-api` reads the newest report of the agents of the page it answers, within
the tenants the caller holds, the way it reads `last_seen`: the cost is the page's.
An agent is **active** while its newest report arrived within twice the interval
it announced — one report lost on the way is not a silence — **late** within five
times, and **silent** after that. An agent whose newest report said it was
stopping is **stopped**, however long ago: somebody stopped it, which is a
different fact from an agent that went quiet. The interval comes from the report
rather than from the platform, because an agent told to report rarely must not
look like one that stopped; what the platform offers will be the descriptor's,
when BE-052 publishes one.

Liveness is an observation, as `last_seen` is, and it moves nothing: no agent is
disabled, revoked or refused because it went silent, and an agent silent on its
status that still sends telemetry is visible as exactly that, from the two
columns side by side.

## What this deliberately does not do

**No findings.** Silence, two sources for one agent — interleaving sequences,
two boots reporting one installation — configuration and policy drift, modules
disabled and restart storms are BE-057's. Every report carries what those need:
an installation identifier, a sequence that never repeats, the boot, how the run
before it ended, the settings digest and the policy revision.

**No fleet gauges.** The gateway and the projector count reports by the condition
they declare, a closed set; how many agents are silent at a given moment is a
question asked of the table, not a metric labelled by agent.

**No second admission window.** A report is admitted on the event window, and
judged on the platform's clock afterwards, so an agent with a slow clock is not
taken for a silent one.

**No status in the registry.** Nothing writes `agents` because a report arrived;
the registry still holds only what was decided.

## Consequences

- **Twelve topics and one more process.** `security.agents.status`,
  `security.agents.status.quarantine` and `status-projector`, which the
  migrators, the images and Compose carry like the others.
- **`Agent` grows three observed fields.** A page carries liveness and
  `last_reported`; reading one agent also carries its newest report. Both read
  `agent_status` through the same connection as `last_seen`, and a store that does
  not answer costs the caller those columns and never the agent.
- **The agent decides what it reports and how often**, between 10 seconds and an
  hour, and never sends a backlog: status is not delivered at the expense of what
  it describes.
