# 12. Storage is owned per workload, and an alert is not a detection

## Context

[ADR 11](0011-a-detection-is-not-an-alert.md) put detections on the backbone and
left them there, durable and unqueryable. Making them queryable means choosing a
store, and choosing one for detections without saying what every other kind of
data needs is how a platform ends up with v1's answer: one PostgreSQL `alerts`
table holding the rule that fired, the ATT&CK attribution, a JSON bag of details,
*and* `status`, `assigned_to`, `acknowledged_at` and `triage_notes` — an
analytical result and somebody's triage in the same row.

v1 also ran PostgreSQL, ClickHouse, Elasticsearch and Redis. Each was a
reasonable local answer; together they are four operational commitments nobody
re-derived. The question this record answers is not "which database" but "what
does each kind of data actually need, and which of those needs exist yet".

## Decision

**Storage is chosen per workload, and a class of data with no producer gets a
stated question rather than an invented answer.**

What exists today, and why:

| class | consistency | volume | access | retention | owner |
|---|---|---|---|---|---|
| **raw telemetry** | at-least-once, deduplicated on merge | highest | append, scanned by time range and tenant | 365 days | ClickHouse `security_events`, written by `event-writer` |
| **detections** | the same | ~1/1000 of telemetry | append, filtered by time, tenant, rule, severity | 730 days | ClickHouse `security_detections`, written by `detection-writer` |

Both are immutable, append-only and analytical, and differ only in volume, so
they share a technology and take a table each. **Detections are kept twice as
long as the telemetry they were made from**, which is the right way round: the
finding is what an analyst returns to, the raw log is bulk, and a detection
carries its own evidence, so it stays readable after the events behind it expire.

What does *not* go there, and why:

- **alerts** — low volume, **mutable**, owned by a person, with a state machine
  (`open → acknowledged → in investigation → resolved / false positive`), an
  actor and an audit trail on every transition. That is a relational workload and
  the opposite of an analytical one. A `ReplacingMergeTree` cannot express "this
  row is assigned to someone and only they may close it";
- **control-plane state** — the agent registry, issued certificates, users and
  roles. Relational, small, strongly consistent;
- **audit** — relational, append-only, and attributable.

**None of those three is created here**, because none has a producer: no rule
materialises an alert yet, and there is no lifecycle API and no identity to
attribute a transition to. Adding PostgreSQL now would be choosing a technology
before the workload it serves exists, which is the mistake this record exists to
prevent. It is named as the answer *when* the producer arrives, and that is all.

Left as a question, not an answer:

- **correlation state** — key, window, TTL, event-time ordering, late events,
  restart, replay, duplication, consistency. Nothing built so far has any state:
  every rule is decided from one event. Model the state, then choose;
- **search indexes** — nothing yet, because no query exists that ClickHouse
  cannot serve. v1 has Elasticsearch because search arrived before its analytical
  store was good enough;
- **inventory and vulnerability findings** — no collector produces either.

**The backbone is the source of truth; a store is a materialisation.** Both
tables can be rebuilt by replaying their topic, and both writers advance their
group position only after a batch is durable. That is what makes it true that
there is no duplicated source of truth: the store is a projection, never an
original.

**A detection is written by a process of its own.** `cmd/detection-writer`
consumes `security.detections`, and it never reads a rule; `cmd/analysis-engine`
decides and never reaches a store. It mirrors `event-writer` exactly, down to the
retry, and the two fail apart: a detection schema problem cannot stop telemetry
being persisted.

**A refused detection goes to a quarantine of its own.** `security.detections`
and `security.events.raw` are different streams, and a refused record carries the
partition and offset it came from — positions that only mean something alongside
the topic they came from. One quarantine per stream keeps a replay tool able to
decode what it reads.

## Consequences

- The domain is not organised around tables. `internal/detectionstore` states
  what a stored detection is and names no driver; `internal/clickhouse` holds the
  client. The architecture test enforces the direction.
- Evidence is stored as five parallel arrays rather than as a document, because
  what a rule read is a contract field path and what the event held is a value,
  and both are worth filtering on. v1 kept the equivalent in JSON and nothing
  could query it. The arrays are one table read sideways and the writer refuses a
  row where they disagree in length.
- `detection-writer` is a fifth process and the fourth long-running one. It earns
  that by having its own failure domain, its own lag and its own group; it is not
  a microservice split for its own sake.
- The store is not the place a detection is *identified*: the engine names it,
  and the table's sort key ends in that name, so a replay replaces rather than
  accumulates. `FINAL` is required of a query that must not see a replayed row,
  which is stated rather than dressed up as exactly-once.
- Two classes are decided and six are not. That is the honest state, and BE-024
  stays open until the producers arrive rather than being closed by guesses about
  them.
