# 34. A stored event is named by the agent that sent it, and a sorting key changes by a rebuild the migrator carries out

## Context

[ADR 12](0012-storage-is-owned-per-workload.md) made `security_events` a
`ReplacingMergeTree` ordered by `(tenant_id, event_time, event_id)`, so that a
batch replayed after a crash collapses back into one row. A `ReplacingMergeTree`
keeps one row per sorting key, and nothing else: two rows that agree on those
three columns are one event to the store, whoever sent them.

Two agents of one tenant that send the same `event_id` for the same instant are
therefore one event. The last insert wins, a hunt reads it `FINAL` and sees one,
and the other agent's event is gone without an error, a metric or a log line.
The 2026-10-02 completeness audit found it (AUD-06), and it is the pattern the
2026-09-26 security audit had already fixed for detections (SEC-01).

Honest agents never meet. The agent names an event by a digest of its
installation and the journal cursor it read, so two installations cannot name an
event alike by accident. But the identifier is the producer's to choose, and the
platform trusts nothing a producer chooses about who it is
([ADR 2](0002-identity-comes-from-the-certificate.md)): a compromised agent that
writes another agent's identifier and instant erases that agent's evidence from
the store. AG-009 asks exactly this of the platform — a forged payload identifier
must not impersonate another agent — and AG-012's downstream idempotency rests
on the same name.

The hunt has the same hole one level up. [ADR 13](0013-a-query-is-a-scope-a-window-and-a-question.md)
resumes a page at the instant and the name of its last record, and for an event
that pair was `(event_time, event_id)`. Even with both rows kept, a page boundary
falling between two agents' events of one identifier and instant skips the one
the page did not end on.

A sorting key cannot be changed in place: ClickHouse lets a key grow only by
columns added in the same statement, and `agent_id` is not new. The store
migrator could not change one either, because it applies only statements that
are idempotent by their syntax. The fix is cheap only while no production data
exists, which is why BE-047 carries a deadline.

## Decision

**An event is named by the agent that sent it as well as by its identifier and
its instant. `security_events` is ordered by
`(tenant_id, event_time, agent_id, event_id)`, and a page of events resumes at
`(event_time, agent_id, event_id)`.**

### The agent comes from the certificate, so the name cannot be borrowed

`origin.agent_id` is the identity the gateway read from the client certificate
and stamped over whatever the agent wrote, so a producer can no longer reach
another producer's row by choosing an identifier. A replay of one agent's event
still has one name and still collapses into one row. The tenant and the instant
stay first, so every hunt prunes exactly as it did; a question about one agent
prunes by tenant and time only, and a data-skipping index is the lever if that is
ever measured to matter, not another sorting key.

A detection keeps resuming at `(event_time, detection_id)`: since SEC-01 its
identifier already carries its tenant and its agent.

### A position is the instant and the names after it, and its layout is signed

A cursor now carries the instant followed by every name the store sorts by after
it — the agent and the identifier of an event, the identifier of a detection —
each with its length. The layout is part of what the cursor's signature covers,
so a cursor written before this change is refused as `invalid_cursor` instead of
being read as some other position, and a cursor written after it is refused by a
plane that has not been upgraded. During a rolling upgrade a caller asks again
from the first page, which is what a cursor that cannot be trusted should cost.

### A sorting key changes by a rebuild

A migration may declare that it rebuilds a table. It holds one statement, which
creates the table as it is to be ordered under a name of its own —
`security_events_rebuild` — and `store-migrator` moves the rows:

1. It notes the newest block the live table has committed, then copies the table
   into the new one, partition by partition, while writers keep writing to it.
2. It exchanges the two names in one statement. A writer inserts by name, so the
   next insert of every writer, of this release or the one before, lands in the
   new table.
3. It detaches the old table synchronously and attaches it again. An insert that
   resolved the old table before the exchange holds it until it ends, and the
   detach waits for every such insert, so from then on the old table holds all it
   ever will.
4. It copies again every part of the old table whose newest block is later than
   the one it noted, and drops the old table.

Copying a row twice is harmless — the new table collapses it exactly as it
collapses a replay — so the procedure always copies more rather than less. A part
merged while the copy ran is selected by the newest block its name carries;
`_block_number` without a persisted column answers the oldest block of a merged
part, and would leave out what arrived after the copy began.

The rebuild resumes from what the store holds, never from what the migrator
remembers: whether the live table already has the declared key, whether the new
table exists and how it is ordered, whether the old one was left detached. A run
stopped before the exchange copies again; a run stopped after it copies
everything the old table still holds, because the block it noted died with it.
`system.detached_tables` also lists tables that were dropped, so whether the old
table was left detached is asked of `ATTACH` itself. A state the procedure does
not produce — the new name present and ordered as declared beside a live table
that already is — stops the migration and asks for a decision rather than
guessing which table holds what.

Measured on the development host (one ClickHouse 24.8, 8 vCPU): 20,000,000 events
across twelve monthly partitions, 1.89 GiB, rebuilt in 56 seconds, while a writer
inserted 2,222 events by name; every one of them was in the rebuilt table.

## What this deliberately does not do

- **Keep both tables, or let a reader choose.** Once the migration is recorded
  there is one `security_events`, ordered one way.
- **Stop the writers.** Telemetry keeps arriving through the rebuild; the price
  is the second copy, not an outage.
- **Recover events the old key already collapsed.** Rows two agents shared were
  merged into one wherever the parts holding them had met; only the ones that had
  not are two rows again.
- **Make every migration procedural.** A rebuild is declared beside its SQL file
  and checked when the schema is loaded: one statement, creating the table it
  names, with a sorting key.

## Consequences

- The first upgrade rewrites the event table once. It needs room for two copies
  of it for the length of the rebuild, and `store-migrator`'s account must be
  able to create, exchange, detach, attach and drop tables in its database.
- `store-migrator` runs once at a time, as it always has. Two runs racing each
  other can undo each other's exchange; both then stop on the state they did not
  expect, nothing is lost, and the next single run completes the rebuild.
- A hunt cursor issued before the upgrade is refused once.
- Writers and readers of the previous release keep working through and after the
  rebuild, because the columns are the same and both address the table by name.
- `store-migrator` reports each migration as it is recorded, and a rebuild as it
  progresses.
- ADR 12's sort key and ADR 13's cursor are amended by this record; nothing else
  in either changes.
