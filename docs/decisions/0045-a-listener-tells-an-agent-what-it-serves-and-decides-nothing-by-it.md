# 45. A listener tells an agent what it serves, from what it runs with, and decides nothing by it

## Context

An agent learns what the platform admits from what its batches are answered.
`seagull.platform.v1.Descriptor` exists, but `control-api` serves it only on the
operator listener, where an agent's certificate cannot reach, and it names the
protocol and the event schema and nothing else: no inventory, status or
assessment schema, no limit, no capability. So the agent of `Seagull-agent-v2`
negotiates nothing before it sends, keeps its own copy of every limit, below the
platform's where it cannot know it (it caps an inventory record at 960 KiB where
the gateway admits 4 MiB), and finds out whether the control plane hands out
updates by asking and being answered `404 agent_updates_not_configured`.

BE-052 asks for every version, limit and capability an agent must respect to be
learnable before it sends anything, on the listener it already reaches, behind
the certificate it already presents, with a capability advertised only when it
is implemented and enabled.

Two facts shape the answer. The ingest gateway and the control plane's agent
listener are different processes serving different things: the gateway admits
four streams, the agent listener renews certificates and hands out policies and
updates, and neither knows what the other was built with. And since
[ADR 37](0037-a-record-is-bounded-by-what-its-topic-carries.md) a record is
weighed after the gateway stamped it — the agent and tenant on its origin, the
reception — so the ceiling a topic carries is not the size an agent may send:
a record of exactly 4 MiB as the agent sends it is refused for good.

## Decision

**Each listener describes what it serves, at `GET /v1/descriptor`, from what it
was built with, and nothing else.** Contracts `v0.21.0` give the descriptor
`streams`, `max_body_bytes` and `capabilities`.

- The ingest gateway describes the streams it routes, each by the admitter that
  judges its batches: the route, the batch and the record by their full names,
  the schema versions the record is read in, the records a batch may carry, how
  old and how far ahead a record may be, and for inventory the items a record and
  a batch may carry. `ingest.Routes` registers every stream at the route its own
  description names and builds the descriptor from the same handlers, so the
  gateway cannot describe a stream it does not route or route one it does not
  describe.
- The control plane's agent listener describes what it offers beside the
  streams: `renewal` and `policy` always, since the listener exists to renew and
  is never built without a policy store, and `update` only when an update store
  and a root were given, which is when it hands one out.

**The descriptor stands behind the gate of what it describes.** On the gateway
it takes the certificate, the registry and the per-agent limiter the streams
take, and answers what they would answer: `403 agent_not_registered`,
`403 agent_not_admitted`, `429`. On the agent listener it takes an agent
certificate, like every route there. An agent the platform refuses learns
nothing it could send.

**A record is described by what an agent may send, not by what its topic
carries.** `max_record_bytes` is the ceiling less the heaviest stamp the gateway
can put on a record: what stamping adds to one that carried no origin and no
reception, at the longest agent, tenant, gateway and batch names the contract
allows. A record that carried an origin grows by no more, since a reception is
replaced whole and an origin gains only the two identifiers. The stamp weighs
285 bytes for every stream today, so an agent may send events, status reports and
assessments of 982,755 bytes and inventory records of 4,194,019. A test admits a
record of exactly that size under the heaviest stamp for every stream, its
origin absent or crossing a length boundary as it is stamped.

**Names are strings.** A stream is named by its route and its record's full
name, a capability by a name the contract lists, and an agent ignores a name it
does not know, so a newer platform describes more to an older agent. An enum
would need a rule for a value the agent's contracts do not declare, which the
agent has deliberately not taken for any reply it reads.

**An entity tag names what is described, `server_time` apart.** It is the
SHA-256 of the descriptor's deterministic encoding without the time, so two
gateways with the same settings tag alike, a changed limit changes the tag, and
`If-None-Match` holding it is answered `304` with no body. An agent asks when it
starts and as often as it likes, and reads a descriptor only when it changed.

**It decides nothing.** Every batch is judged on its own against the same limits,
whether or not its agent asked; nothing records who read a descriptor.

## What this deliberately does not do

**No limit of a field.** The longest a text may be is the contract's, fixed by
its schema version, and an agent reads it there.

**No rate or capacity.** The per-agent budget and what the process holds at once
are the process's, not a stream's; they are answered `429` and
`503 gateway_at_capacity` with `Retry-After`, which an agent already honours.

**No reporting interval.** Offering one is what remains of BE-053.

**The operator listener's descriptor is unchanged.** It still names the protocol
and the event schema, for whoever reads it there.

## Consequences

- Contracts `v0.21.0`; the backend moves to it. Nothing an agent sends changes.
- `If-None-Match` is read by one function, `httpx.Unchanged`, for the descriptor,
  the policy and the update an agent is handed; it reads every line of the
  header, where the policy and update routes read only the first.
- The agent can read its limits, schemas and capabilities instead of keeping
  copies of them; that is its own work (AG-003, AG-013, AG-024).
- The descriptor is an agent-visible answer, so BE-056 records it with the rest.
- A limit an operator changes changes the tag on the next start, and an agent
  asking with the old tag reads the new descriptor.
