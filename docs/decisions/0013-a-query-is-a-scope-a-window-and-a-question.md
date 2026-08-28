# 13. A query is a scope, a window and a question

## Context

[ADR 12](0012-storage-is-owned-per-workload.md) made the store a materialisation
of the backbone and left two tables nobody reads. A materialisation nobody can
read is a backup: the platform can find that somebody failed a hundred SSH
passwords and cannot show a person the hundred.

v1 could show them, and the way it did is the warning. Hunting there had three
dialects — `simple`, `kql` and `eql` — chosen by a prefix on the search string or
by a query parameter, one of them a hand-written parser compiling to
Elasticsearch, one of them handed to Elasticsearch whole. Elasticsearch existed
because search arrived before the analytical store was good enough, so a hunt
answered from a different copy of the data than the dashboards, behind a circuit
breaker and a fallback path to ClickHouse that answered a slightly different
question. The parts worth keeping are the operational numbers — thirty days of
lookback, five hundred records to a page, thirty-two clauses to a query — and the
cursor, which was a signed keyset and was right.

The question this record answers is what a query *is*, before anything is built
that answers one.

## Decision

**A query is a scope, a window and a question, in that order, and only the last
of the three comes from the caller.**

### The read plane is a process of its own

`cmd/query-api` is the sixth executable and the only one holding a read
connection to the analytical store. It consumes no topic and writes nothing.

It earns the split the way `detection-writer` did. An analytical read over a
month of telemetry is a different workload from an administrative write, and the
two must fail apart: the surface an operator uses to act on an attack cannot go
down because somebody asked an expensive question about it. `control-api` never
opens a store connection, so an administrative endpoint cannot grow into a query
one by accident.

### The scope is not a filter

A `hunt.Query` has no exported fields and is only ever built by a compiler that
takes a `hunt.Scope`. An empty scope is refused. There is no query parameter, no
header and no predicate that widens it, and the tenant condition is the first
thing in every statement the adapter builds. Authorisation is therefore
structural rather than a check somebody can forget to write.

**The scope comes from the caller's certificate**, exactly as an agent's identity
does in [ADR 2](0002-identity-comes-from-the-certificate.md): the common name
says who is asking and the organisation says which tenants they may read. The
listener has no plaintext mode and no mode without a client certificate
authority, because without one there is nobody to be authorised as. When there is
an identity service to ask — BE-028 — the scope is derived from a token instead
and nothing below that line changes.

### The window is required and bounded

Both tables are partitioned by the instant the thing happened. A question without
a horizon is a question about everything ever collected, so the range is part of
the query rather than a predicate in it, it is half open, and it may not be wider
than the plane allows.

### A query names the contract, not the store

A caller writes `authentication.user.name`, never `auth_user_name`. The
vocabulary is built by walking the contract message each dataset projects, which
is how [ADR 6](0006-a-rule-addresses-the-contract.md) built the rule vocabulary
and for the same reason: v1 kept a dictionary from caller-facing names to storage
columns, and the fields that did not fit ended up in a JSON bag nothing could
query.

The mapping from a field to a column exists in exactly one place,
`internal/clickhouse`, and it runs one way. It is total in both directions and
checked when the process starts, so a contract field with nowhere to live stops
the process rather than silently answering nothing.

A query can address one thing a rule cannot: **time**. A rule decides one event
against a literal and a window is not a predicate; a hunt is a window before it
is anything else, and the store keeps every instant the contract carries.

### The query model is the query, and a dialect would compile into it

There is no parser. The model — a range, a boolean tree of predicates, a limit
and a cursor — is what the server executes, and a text dialect is a reader that
produces one, exactly as `internal/rulefile` reads a document and produces a
`detection.Rule`. A dialect that is the query has to be reimplemented wherever
the query is needed; a dialect that compiles into the query can be replaced.

The tree is a full one — `all`, `any`, `not` and a predicate — rather than the
conjunction the first callers will need, because a dialect that cannot express
`a or b` across two fields cannot compile into a model that cannot either.

### The limits are part of the language

Structural, because a caller who needs more than this is asking for a report and
a report is not a hunt: **32 predicates, 8 levels of nesting, 256 literals to a
predicate, 512 bytes to a literal**. Configured, because they depend on the
deployment: the widest window, the page size and its ceiling, the read budget and
how much of the store one read may examine. The budget is a deadline as well as a
setting the store is asked to honour, so a source that ignores its own limit
cannot hold a caller open.

There is no regular expression and no wildcard, which is the same decision the
rule language made: a pattern hands the caller control of how much of the store a
question reads.

### A page is resumed by a key, and the key belongs to the query

The cursor is the sort key of the last record — the instant and the name — signed
with a key the server holds. An offset re-reads everything it steps over and
moves under a concurrent write; a key does neither, and both tables are sorted by
exactly that pair.

**The query that issued a cursor is signed along with it.** Page two of one
question cannot be spent on another, so a page cannot arrive under a wider scope,
a wider window or different filters than the page before it.

### A page is read `FINAL`

A replayed record is a second row until the parts holding it are merged, and an
analyst reading the same event twice has no way to tell that from the same thing
happening twice. ADR 12 said `FINAL` is required of a query that must not see a
replay; this is that query.

### What is read back is the contract message

`eventstore.Restore` and `detectionstore.Restore` are the inverses of the
projections beside them, and the round trip is a test rather than a claim. A page
of a hunt is `seagull.event.v1.Event` and `seagull.detection.v1.Detection` — the
records that crossed the backbone — so a reader never learns a second vocabulary
and no second event model exists to drift from the first.

## Consequences

- **There are two operator languages in the tree**, one in `internal/detection`
  and one in `internal/hunt`, and the names overlap. They are not the same
  language: one decides an event held in memory and the other is compiled into a
  read of a projection; one deliberately cannot address time and the other must;
  one asks whether a field is absent from a message and the other asks a column
  that cannot distinguish absent from empty. Sharing them would make a change to
  the rule language a change to the query language. What matters is shared
  already — both address the contract, and neither has a dictionary.
- **Evidence is asked about as columns, not as entries.** The five arrays are one
  table read sideways, so `evidence.field equals X and evidence.held equals Y`
  finds a detection where some entry read X and some entry held Y, not
  necessarily the same one. Correlating a position across the arrays is a
  different question and is not asked yet.
- **A short page does not mean the range is exhausted**; only an empty one does. A
  store answers within a budget and can return fewer rows than it holds, so a
  page that carried anything is always followed by a cursor. It costs one more
  round trip at the end of an answer and it never skips a record.
- **Cursors do not survive a restart** unless a key is configured, and more than
  one replica behind one address has to be given the same key or a page resumes
  on whichever replica issued it and nowhere else.
- **There is no aggregation, no free-text search and no relevance.** "How many
  failures per host" is a different shape of answer and would want a different
  contract; nothing here should be stretched into it.
- **A query can still be expensive.** The window, the budget, the row ceiling and
  the page size bound it, and `contains` over a month of raw records will spend
  all of them. That is what the metrics and the separate process are for.
