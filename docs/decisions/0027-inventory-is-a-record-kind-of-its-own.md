# 27. Inventory is a record kind of its own, and what an asset currently has is what the newest full scan named

## Context

[ADR 12](0012-storage-is-owned-per-workload.md) decided two classes of data and
left six as questions rather than answers. One of them was named in a single
line:

> **inventory and vulnerability findings** — no collector produces either.

BE-034 brings the producer, so the question comes due. An endpoint agent reads
what a machine has — its distribution, its kernel, its installed packages, its
services, its interfaces, its local accounts, its hardware, its running
processes — and the platform has to turn a stream of those readings into one
consistent answer to "what does this asset have right now".

The cheap answer is to make it telemetry. `seagull.event.v1.Event` already has an
`event_class`, an envelope the gateway stamps, a topic, a store, a writer and a
365-day table. Adding `EVENT_CLASS_INVENTORY` and a body would reuse all of it and
cost one contract release.

It is the wrong answer, and the four reasons below are why. They are recorded
because the cheap answer will look attractive again the next time a record kind
arrives.

## Decision

**Inventory is a record kind of its own — its own contract, topic, store and
process — and the current state of an asset is the set of items the newest full
scan of that kind named.**

### Why it is not a class of event

1. **It is the grain the platform already uses.** Every record kind in V2 has its
   own contract package, its own topic, its own owner and its own store:
   `event`/`security.events.raw`, `detection`/`security.detections`, `alert` and
   `incident` in PostgreSQL, `agent`/`security.agents`,
   `ruleset`/`security.rulesets`. Inventory is a new record kind, not a variation
   of an event. `seagull.agent.v1.Admission` is the closest precedent: a record
   projected into current state by whoever reads it.

2. **ADR 12's own method says they are different workloads.** `security_events`
   keeps 365 days and is scanned by the hunt. An estate reports one or two orders
   of magnitude more package observations than authentication events — a fat
   server carries a few thousand packages and reports all of them on every scan —
   so inventory would dominate that table's partitions, its TTL and every hunt
   query's scan, in order to hold "openssl is still installed" for a year.

3. **A shared topic would make detection latency a function of inventory volume.**
   `analysis-engine` consumes `security.events.raw`. A fleet-wide scan would be
   millions of records it must fetch and decode in order to route them to nothing,
   and its consumer lag — the signal an operator reads as "detection is behind" —
   would stop meaning detection. A topic of its own also keeps the cheap door
   open: the engine can subscribe to inventory **when a rule needs it**, rather
   than always.

4. **An event is one observation and a snapshot is a set.** `security_events` is
   one row per event, so a shared envelope would force one record per package, and
   with it the loss of the only thing that makes absence mean anything: that this
   list was complete when it was taken. A contract of its own carries a whole scan
   as one record keyed by the asset, which is what snapshot-versus-delta and the
   out-of-order policy are expressed in.

### The envelope is reused rather than copied

`seagull.inventory.v1.Record` carries `seagull.event.v1.Origin`, `Collection` and
`Reception`. The gateway stamps identity, tenant and reception with the same code
it stamps an event with, so [ADR 2](0002-identity-comes-from-the-certificate.md)
and [ADR 26](0026-an-agent-sends-into-the-tenant-it-was-registered-in.md) apply
to inventory unchanged and without being restated: a collector cannot choose its
own agent identifier and cannot place its records in another estate.
`internal/event.ValidateOrigin` and `ValidateCollection` are exported for exactly
this, rather than a second copy of the same rules drifting from the first.

`POST /v1/inventory` stands behind the same gate as `POST /v1/events` — the same
verified certificate, the same roster, the same rate limiter, the same
process-wide capacity bound and the same body ceiling — because what an agent may
spend and what the process may hold are bounded per agent and per process, not per
kind of record. The two routes differ only in what a payload decodes to and where
it is published.

### An item's identity is derived and never read off the wire

`internal/inventory.ItemID` is a sha256 over the kind and the **length** of every
identifying part, so no two identities can be spelled into each other by a name
that happens to contain a separator. The platform derives it; a producer never
sends one. Two collectors that named the same package differently would otherwise
leave an asset holding it twice, and a replay would not land on the row it wrote
the first time.

What identifies an item is a decision per kind, and two of them are worth stating:

- **A package is identified by its name, architecture and manager, and not by its
  version.** An upgrade is the same package at a new version, so it replaces the
  row rather than adding one. Two rows would leave an asset holding both, and the
  vulnerable one would never stop matching.
- **An account is identified by its uid, falling back to its name when the
  collector gives no uid.** A renamed account is the same account; a freed name
  reused by another account is a different one.

### Current means "named by the newest full scan"

The projection is one row per `(tenant_id, agent_id, kind, item_id)` in
ClickHouse `asset_inventory`, carrying the item's own fields and `last_seen`, and
a second table `asset_inventory_scans` holding one row per
`(tenant_id, agent_id, kind)` with the `scanned_at` of the newest full
enumeration. **The current items of a kind on an asset are those whose
`last_seen` is at or after that asset's `scanned_at` for that kind.**

That one sentence is the whole of the update semantics:

- **A snapshot moves the line.** It writes every item it names and sets
  `scanned_at`. Anything it did not name keeps its older `last_seen` and is
  therefore no longer current, with `last_seen` saying when it was last there.
- **A delta never moves the line.** It refreshes the items it names and says
  nothing about what it omits, which is why `Mode` is in the contract. A delta
  that moved the line would retire every item it did not happen to mention. An
  item a delta introduces is current immediately, because a delta is newer than
  the line it did not move.
- **An empty snapshot is admitted and an empty delta is refused.** An empty
  snapshot is how a collector says the asset has none of that kind left: it writes
  no items and moves the line past every item there was. An empty delta states
  nothing at all.
- **Nothing is ever deleted and nothing is tombstoned.** An item that went away
  leaves the row that says when it was last seen, and it is out of the answer
  because the line moved past it. The card's "stale/last seen semantics" falls out
  of the same two columns rather than needing a third.
- **Staleness is the same line read the other way.** An asset whose `scanned_at`
  is nine days old is reporting a nine-day-old package list, and a reader can see
  that rather than assume the answer is current.

### Out of order is decided by the collector's clock

`asset_inventory` is a `ReplacingMergeTree(last_seen)` and
`asset_inventory_scans` a `ReplacingMergeTree(scanned_at)`. **A record whose
`collected_at` is older than what the row already holds never overwrites it** —
it loses on merge and, at read time, to `FINAL` or `argMax`. A record that took
the long way round therefore cannot put a package back to the version it was
three scans ago, and a late snapshot cannot drag the line backwards.

Neither table has a `PARTITION BY`, and that is load-bearing rather than an
omission: a `ReplacingMergeTree` collapses rows of one key only within a
partition, and every candidate to partition by here is a time that moves as the
item is observed again. Partitioning would leave one installed package as a row
per month that no merge ever reconciles. What bounds the tables instead is a TTL
on `last_seen`, which drops an item nobody has seen for a year.

### A record is folded whole or refused whole

`cmd/inventory-projector` consumes `security.inventory.raw` in a group of its
own, refuses what it cannot read to `security.inventory.quarantine`, and advances
its position only after the batch is durable. **One item the store cannot hold
takes its whole record with it, its scan included**, because a scan whose items
never landed would retire everything the record was about to confirm.

It is the eighth long-running process and earns that the way `detection-writer`
does: a failure domain of its own. An inventory schema problem must not stop
telemetry being persisted, and a fleet-wide package scan must not become the
reason a login is late.

### The projection is a materialisation and the topic is the source of truth

Both tables are rebuilt by replaying `security.inventory.raw`. Folding the same
record twice leaves one item and one scan, because identity is derived and the
engine replaces on it. That is the card's second acceptance criterion, and it is
what makes the projection safe to drop and rebuild.

## What this deliberately does not do

**No `first_seen`.** It cannot be kept correctly under a `ReplacingMergeTree`,
where the newest row wins wholesale: the column would be overwritten with the
newest observation's time on every scan, which is `last_seen` under another name.
Keeping it truthfully needs an aggregating engine or a read before every write,
and neither is justified by anything the card asks for. A column that lies is
worse than a column that is absent. When something needs it, the honest
implementation is an aggregating projection over the same records.

**No index and no ClickHouse `PROJECTION` for the reverse lookup.** "Which assets
have package X" is BE-036's question, and it is not free: the sort key serves
"everything about asset A". A `PROJECTION` is not the answer it looks like — a
query with `FINAL` will not use one, and a query without `FINAL` reads rows that
were replaced — so the access path is left to the card that has the query.

**No read route.** Nothing reads inventory back yet, so there is no query-plane
endpoint and no exported "current items" method. The definition lives in the
schema and is executable in the integration suite; BE-036 and the query plane will
own the read.

**No vulnerability matching.** `Package.manager` travels with the name and version
precisely so that the ecosystem a version string is interpreted in is a fact the
collector recorded rather than one inferred later, but nothing matches yet. That
is BE-035 and BE-036.

**No agent.** `Seagull-agent-v2` is empty. `tools/devprobe -inventory` is the only
producer and sends an operating system, a package list and a service so that
`make up` walks the whole path. No delta producer exists either; the mode is in
the contract because the projection cannot be designed without it, not because
something sends one today.

**No second tenancy mechanism.** Inventory is placed by the registry exactly as
telemetry is. There is nothing here about tenants that ADR 26 does not already
say.

## Consequences

- **`Rejection.event_index` indexes a record when the batch is inventory.** The
  contract says so rather than a second field being added; renaming it would
  strand deployed agents for nothing.
- **Two topics and two tables more.** `security.inventory.raw` is keyed by the
  agent, so every scan of one asset is read in the order it was written — which is
  what decides whether an item is still installed, and what two partitions would
  not agree on. `security.inventory.quarantine` is a quarantine of its own for the
  reason ADR 12 gives: a refused record's partition and offset only mean something
  alongside the topic they came from.
- **The ingest gateway serves two routes behind one gate.** `internal/ingest`
  names the record kind it admits as a `stream`, so the certificate, roster,
  limiter, capacity and body ceiling exist once. A third kind of record costs a
  decoder and a publisher, not a second copy of the admission path.
- **Inventory bounds are the contract's, not the store's.** 10,000 items per
  record and 20,000 per batch are declared in `internal/inventory`, and the
  ClickHouse schema is derived from them. A batch is bounded by records *and* by
  items, because a dozen records is a few kilobytes or a hundred megabytes
  depending on what the asset was observed to have.
- **ADR 12 has five open classes rather than six.** Inventory has a producer, a
  workload and an owner, so it stops being a question. Vulnerability findings,
  correlation state and search indexes remain.
