# 53. A stored event keeps the position it was read from, and of an event delivered twice the store keeps the arrival the engine decided

## Context

A counting detection is named by the event that reached the threshold, and
whether an event reaches it is decided when the event arrives, from what its
key holds then (`analysis.Engine.reached`, `detectionstate.held.observe`). The
window is kept in event time; the decision is made in arrival order. With a
threshold of two, the same two events arriving the other way round are one
detection under the other event's name. BE-073 asks a backtest of the active
ruleset to reproduce stored detections under the same identifiers, so it has to
read the events of a partition in the order the engine read them.

The store cannot give that order back.
[ADR 34](0034-a-stored-event-is-named-by-the-agent-that-sent-it.md) orders
`security_events` by `(tenant_id, event_time, agent_id, event_id)`, the instant
is kept to the millisecond, and nothing says where the backbone held a row.
Events of one agent that share a millisecond, or that the agent delivered out of
order (AG-012, AG-013), read back in another order than the engine read them.
The raw topic keeps seven days and the store 365, so after a week the store is
the only account of what arrived.

An event is also delivered twice in the ordinary course. An agent whose
acknowledgement is lost sends the same batch again (AG-012), the gateway
publishes it again under a new `reception`, and the topic holds two records of
one event. The engine decides on the first: the second finds its name already in
the key and decides nothing. The store keeps one row per event, and
`security_events` is a `ReplacingMergeTree` with no version, which keeps the row
inserted last — the second arrival, its reception and, once rows carry one, its
position. A backtest reading that position places the event where the engine
never decided it:

```text
threshold = 2      A at offset 10, B at 11, A again at 15

engine:  A counted, B reaches the threshold      named after B
store:   B at 11, A at 15                         read back, named after A
```

Which of two rows a `ReplacingMergeTree` keeps is set by its version, a parameter
of the engine, and ClickHouse changes no engine in place (26.8 has no
`ALTER TABLE ... MODIFY ENGINE`). Only rows written before production data are
cheap to give a position, and only a table rebuilt before then is cheap to
rebuild: a row stored without its position can never be given one.

## Decision

**A stored event keeps the partition and offset of the record its row was
written from, and of an event delivered twice the store keeps the earliest
arrival.**

### The position is the writer's, taken from the record it consumed

`security_events` gains `log_partition Int32` and `log_offset Int64`, beside the
reception they belong with. `event-writer` places each row at the record it
decoded it from; `eventstore.Project` of an event alone places it nowhere. Nowhere
is -1 in both, Kafka's own word for no offset, because offset zero is where every
partition starts. A row stored before positions were kept reads -1, the default
the columns are created with, and so does a row a writer of an earlier release
stores while an upgrade is under way, since it does not name the columns.

### The first arrival is kept

```sql
arrival_precedence Int64 MATERIALIZED -log_offset
ENGINE = ReplacingMergeTree(arrival_precedence)
```

A `ReplacingMergeTree` keeps the row with the highest version, and the negated
offset makes the earliest position the highest — under `FINAL`, within one
insert, and in every merge. The whole row kept is the first arrival's: its
reception as well as its position, so what a row says about when, where and in
which batch the platform received an event is what the engine decided from.

A row without a position precedes every row with one. It was stored before
positions were kept, so it arrived before any of them, and "no position" is
honest where the later position would be wrong. The price is a record a writer of
this release reads again after a writer of the earlier one stored it — a
partition handed over during the upgrade — which keeps no position.

### What a change in the partition count does

The raw topic is keyed by the agent (`broker.PartitionedBy`), so all of one
agent's events are in one partition and their offsets are the order the engine
read them in. `backbone-migrator` refuses to change a topic's partition count. If
an operator changes it anyway, the producer's partitioner moves an agent to
another partition from that moment: its earlier events keep their positions in
the first, its later ones take positions in the second, the two sequences do not
compare, and the engine read the two partitions in an interleaving no position
records — the situation [ADR 39](0039-a-detection-is-named-by-the-agent-and-identifier-of-every-event-that-decided-it.md)
describes across agents. An event sent again across the change keeps whichever
arrival has the smaller offset, which need not be its first. A topic deleted and
created again starts its offsets over, so positions from before and after it
name the same numbers for different records. Neither is an operation the
platform performs; both are stated here rather than handled. A reader recognises
the first by one agent's events found in two partitions.

### A table is rebuilt to its shape, not only to its key

Migration 13 rebuilds `security_events` by ADR 34's procedure. A table counts as
rebuilt when its shape — the engine with its parameters and the sorting key, as
`system.tables` reports them — is the declared one. Compared by its key alone,
`security_events` already looks rebuilt, and the migration would be recorded
without a row moving. The copy names the columns both tables hold: a column the
old table lacks takes its default, and a column the store computes is computed.

Measured on the development host (one ClickHouse 26.8, 8 vCPU, 15.5 GiB):
10,000,000 events across twelve monthly partitions, 1.28 GiB, rebuilt in 22
seconds while a writer of the earlier release inserted 148 events by name; every
one of them was in the rebuilt table, and no row stored before it was given a
position.

### A partition's events are read in position order by the sorting key and a sort

The backtest's read is a tenant's events of an event-time window, each
partition's in the order the engine read them:

```sql
SELECT ... FROM security_events FINAL
WHERE tenant_id = ? AND event_time >= ? AND event_time < ?
ORDER BY log_partition, log_offset
```

The window is selected by the prefix of the sorting key, `FINAL` keeps the first
arrival of every event, and the sort orders what is left. No structure is added
for it. Measured on 20,000,000 arrivals over 48 hours on twelve partitions (three
tenants, 1 % delivered up to 30 minutes late, 0.5 % sent twice), for the tenant
holding 90 %:

| window | rows | in position order | peak memory | read alone |
|---|---|---|---|---|
| 1 hour | 375,326 | 0.30 s | 327 MiB | 0.11 s |
| 6 hours | 2,251,791 | 1.17 s | 1.50 GiB | 0.34 s |
| 24 hours | 9,002,555 | 5.0 s | 4.13 GiB | 1.27 s |

Memory grows with the window, about 470 bytes for each row of it, and an external
sort does not bound it for rows this wide (held to 1 GiB: 7.4 s and 2.88 GiB).

Two alternatives were measured and not taken:

- one query per partition, filtered and sorted on its own: 22.1 s for the
  24-hour window at 1.02 GiB, because every query reads the whole window again;
- a lightweight projection, `(SELECT _part_offset ORDER BY tenant_id,
  log_partition, log_offset)`, read by offset range: 9.1 s at 791 MiB. It writes
  on every insert and merge of the busiest table (+4 to 7 % insert time, +13 %
  merge time, +5 to 6 % on disk), a `ReplacingMergeTree` holds one only under
  `deduplicate_merge_projection_mode`, `FINAL` never uses it, so its reader keeps
  the first arrival itself, and an offset range returns events outside the
  window. It can be added later by `ADD PROJECTION` and `MATERIALIZE PROJECTION`
  without a rebuild (1.4 s for 20,000,000 rows); BE-073 decides when a window's
  memory is more than a backtest may spend.

## What this deliberately does not do

- **Reorder what exists.** The sorting key is ADR 34's.
- **Keep every arrival.** An event is one row; the position of an arrival the
  engine decided nothing on is not kept.
- **Promise identifiers across agents.** A rule grouping across agents is decided
  in an order no partition's positions record (ADR 39); what a backtest promises
  for it is BE-073's to state.
- **Show a position to a hunt.** A position is not a field of the event contract,
  and `eventstore.Restore` gives back the event.
- **Build the backtest's reader**, or give rows stored before this record a
  position.

## Consequences

- The first upgrade rebuilds `security_events` again; it needs room for two
  copies of the table while it runs.
- `reception` of an event sent twice says where it first arrived, so a hunt for
  the batch it was sent again in does not find it, and the newest ingest time
  `control-api` reads as an agent's last telemetry no longer moves on a batch sent
  again once its parts merge.
- Rows stored before this record, and rows an earlier writer stores during the
  upgrade, hold no position, and a backtest says it cannot place them.
- Every table that will store events is created with the two columns and the
  same version (BE-063).
- `store-migrator` logs the engine a rebuild moves a table to beside its key.
- [ADR 12](0012-storage-is-owned-per-workload.md) and ADR 34 are amended by this
  record.
