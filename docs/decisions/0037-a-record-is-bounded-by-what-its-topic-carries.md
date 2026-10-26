# 37. Every topic declares the largest batch it carries, and the gateway admits no record its topic would refuse

> Amended by [ADR 40](0040-a-record-the-platform-makes-is-bounded-where-it-is-made.md):
> what the platform makes itself is bounded where it is made — a rule by the
> heaviest detection it could make, refused as it is compiled, and a ruleset by
> the log it is published to, refused at publication — and every text the event
> contract carries is bounded, its reception included.

## Context

[ADR 1](0001-durable-before-acknowledged.md) answers `503` when the backbone did
not take a batch, and an agent keeps its copy and sends it again. That is only
true backpressure when sending again can succeed.

It could not for a large inventory record. The gateway admits up to 10,000 items
in one record and 8 MiB in one body; nothing bounded what the record encodes to.
The producer refused any batch above franz-go's default of 1,000,012 bytes, a
number nobody in the platform chose, and the topic would have refused one above
the broker's default of 1 MiB. Measured, a package as dpkg reports it on
Debian 12 encodes to 191 bytes, so 10,000 of them are 1,910,093 bytes: admitted,
validated, refused by the producer, answered `503`, and sent again by the agent
forever, with its inventory route stuck behind it. The 2026-10-02 completeness
audit recorded it (AUD-02, BE-045), and the agent hides it by capping a record at
960 KiB on its side.

Auditing every topic found the same hole in every stream the gateway admits. A
decoder keeps the fields it does not know and the encoder writes them again, so
an event, a status report or an assessment carrying undeclared fields passes
every field bound and still weighs whatever the body ceiling allows. And no topic
said what it carries: a quarantine took the defaults of its stream, so the copy
of a refused record, which travels with its reason in headers, could be larger
than the quarantine would take, and the consumer refusing it would stop on it.

## Decision

**Every topic declares the largest record batch it carries**, `max.message.bytes`,
derived from the largest record its producers may write plus 64 KiB for the key,
the headers and the framing of a record and its batch, and never less than the
1 MiB a broker takes by default: a smaller batch would only send small records
in more requests. **A quarantine carries its stream's batch plus 64 KiB**,
because a refused record is copied whole and its reason travels beside it; that
reason is cut at 4 KiB, on a character, so the room beside the copy is a bound
rather than a hope. The declaration is derived rather than configured, so a
deployment cannot set a topic below what its producers write.

**The migrator applies it and every process verifies it before it serves, as a
promise.** A topic carrying less than the topology declares refuses a record the
platform already admitted, which is a wrong answer rather than a degraded one, so
a process facing one refuses to start and names `backbone-migrator`; a topic
carrying more is reported as drift. Redpanda answers for the setting, so drift
is visible, as it is not for `min.insync.replicas`.

**Every producer builds batches no larger than its topic carries**, told by the
executable from the topology, and refuses to start without being told. A ceiling
the client chose for itself is what refused the inventory record; one larger than
the topic would build a batch the broker refuses whole.

**Every record kind the gateway admits declares the bytes it may encode to, and
the gateway weighs each record as it publishes it** — after stamping identity,
tenant and reception — before anything is produced. A record above its ceiling
is refused for good by its position: `422` with the code the route already uses
for a record it refuses (`invalid_record`, `invalid_event`, `invalid_report`,
`invalid_assessment`), the record's index and the field `record`, `event`,
`report` or `assessment`. A deployed agent already reads that answer as the
platform's final word on that record and stops sending it; a code of its own
would be read as unexpected and sent again forever, which is the defect.

| Kind | Ceiling | Why |
|---|---|---|
| inventory record | 4 MiB | twice the 1.9 MB that 10,000 packages encode to as dpkg reports them, for longer names and other managers |
| event | 960 KiB | what a topic carries by default less its framing; the largest event the field bounds admit is about 6.5 KB |
| status report | 960 KiB | the same; the largest report the field bounds admit is under 120 KB |
| assessment | 960 KiB | the same; 512 results at their bounds are about 310 KB |

The three at 960 KiB refuse nothing a field bound admits; they refuse only what
undeclared fields make heavy. Inventory is the one kind whose honest records
outgrow a default topic, so it is the one whose topic carries more.

**The weight is a rule of admission, never of replay.** Each kind's `Validate`
weighs a record and its `ValidateContract`, which every consumer applies, does
not: a record a topic holds was carried, and only admission decides what the
backbone is asked to carry. It costs a `proto.Size` per record. Measured on
1,000-event batches, admitting an event went from 849 to 1,255 ns, about a
tenth of what the gateway spends on an event once decoding and encoding are
counted; the stores and the engine pay nothing.

**A larger ceiling rather than a snapshot in parts.** A chunked snapshot needs a
scan identity, an assembler and a projection that folds several records as one
transaction, or ADR 27's "the newest full scan" stops being one record. Nothing
measured needs it: the item ceiling encodes to less than half the byte ceiling.
It stays the answer if an estate measures scans above 4 MiB.

## What each topic carries

| Topic | Written by | Largest record | Bounded where | Carries |
|---|---|---|---|---|
| `security.events.raw` | `ingest-gateway` | 960 KiB | admission | 1 MiB |
| `security.events.quarantine` | `event-writer` | its stream's batch | the stream | 1 MiB + 64 KiB |
| `security.detections` | `analysis-engine` | unbounded where it is made | consumers refuse above 256 KiB | 1 MiB |
| `security.detections.quarantine` | `detection-writer` | its stream's batch | the stream | 1 MiB + 64 KiB |
| `security.inventory.raw` | `ingest-gateway` | 4 MiB | admission | 4 MiB + 64 KiB |
| `security.inventory.quarantine` | `inventory-projector` | its stream's batch | the stream | 4 MiB + 128 KiB |
| `security.advisories` | `advisory-importer` | 768 KiB | the importer | 1 MiB |
| `security.advisories.quarantine` | `advisory-writer` | its stream's batch | the stream | 1 MiB + 64 KiB |
| `security.rulesets` | `control-api` | unbounded where it is made | nowhere | 1 MiB |
| `security.agents` | `control-api` | an admission: five fields under 200 bytes | its fields | 1 MiB |
| `security.agents.status` | `ingest-gateway` | 960 KiB | admission | 1 MiB |
| `security.agents.status.quarantine` | `status-projector` | its stream's batch | the stream | 1 MiB + 64 KiB |
| `security.assessments` | `ingest-gateway` | 960 KiB | admission | 1 MiB |
| `security.assessments.quarantine` | `assessment-projector` | its stream's batch | the stream | 1 MiB + 64 KiB |

A topic added tomorrow declares its batch or `Topic.Validate` refuses it, and a
producer for it refuses to start until it is told.

## What this deliberately does not do

**It does not bound what the platform makes itself.** Two producers write records
nothing weighs where they are made. `analysis-engine` can make a detection whose
evidence exceeds the 256 KiB its consumers take — evidence is one entry per
comparison a rule makes, and a rule's comparisons are bounded only by its
document — so the writers quarantine it, and above what the topic carries the
engine retries it forever and stops its partition. `control-api` publishes a
ruleset whose documents are bounded at 1 MiB, but an alias in a document repeats
what it names, so a ruleset can compile to more than its topic carries, and the
publication is answered `503 publish_failed` when it can never succeed. Neither
is reachable from an agent; both need an operator's rule, and both are carried
by BE-094, which bounds a rule's detection when the rule is compiled and refuses
a ruleset heavier than its topic as the invalid ruleset it is.

**It does not weigh what a consumer reads**, for the reason given above.

**It does not move the agent.** The agent still caps an inventory record at
960 KiB; raising its cap to the platform's 4 MiB is AG-024's to decide, and an
older agent stays compatible because it only ever sends less.

## Consequences

- **A topic the migrator has not reached stops the processes that use it.** The
  inventory topics now declare more than a broker's default and every quarantine
  declares 64 KiB more than its stream, so after an upgrade the gateway, the
  writers and the projectors refuse to start until `backbone-migrator` has run.
  Compose already runs it first.
- **Producers build larger batches.** Their ceiling moves from 1,000,012 bytes to
  what their topic declares, at least 1 MiB, which changes nothing a broker sees
  beyond records it used to refuse.
- **An agent sees `422` where it used to see `503`** for an inventory record above
  4 MiB, and for any record heavier than 960 KiB that only undeclared fields could
  have made. The agent's recorded exchanges with backend `0656b2a` still show the
  `503` and need recording again.
- [ADR 27](0027-inventory-is-a-record-kind-of-its-own.md) is amended: a record's
  items are bounded by count and its encoding by bytes.
