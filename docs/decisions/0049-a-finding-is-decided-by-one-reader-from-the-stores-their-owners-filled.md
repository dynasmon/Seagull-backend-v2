# 49. A finding is decided by one reader from the stores their owners filled, and kept as one row for each episode of exposure

## Context

[ADR 27](0027-inventory-is-a-record-kind-of-its-own.md) keeps what every asset
has, [ADR 43](0043-a-record-keeps-apart-what-one-identity-would-fold.md) names
each item, and [ADR 28](0028-vulnerability-intelligence-is-read-from-its-source.md)
keeps every version of every advisory the platform read. BE-036 joins the two:
which package of which asset is affected by which vulnerability, with a lifecycle
a person can follow, reproducible from identified inventory and intelligence,
the same under replay, and never resolved by intelligence that failed to arrive.

Five things make that harder than a join:

1. **Two streams fill the two stores at their own speed.** An inventory record
   evaluated before the advisory that affects it is stored, and the advisory
   evaluated before the record is stored, would each miss the other, and nothing
   would ever bring the pair together.
2. **A label is a comparison with the past.** `REINTRODUCED`, `opened_at` and
   every closing of the contract (`v0.22.0`) say how a decision differs from the
   one before it, so the matcher has to read what it decided last.
3. **Two evaluations of one asset at once disagree.** Both would read the same
   past and label against it; whichever is stored second contradicts the first,
   and nothing corrects it afterwards.
4. **An asset is assessed whole every day.** The contract holds an asset's open
   findings to its newest whole assessment, so every open finding is decided again
   with every scan an agent sends. A store with one row per decision grows by a
   row per open finding per day.
5. **A gap in intelligence is not an answer** (ADR 28), and neither is a package
   the platform cannot read.

V1 resolved every finding of an agent whenever its OSV query was skipped, named a
finding by its OSV id so one CVE became several, and compared binary names with
advisories that name source packages. The card lists all three as failures to
avoid, and nothing of V1's structure is reused.

## Decision

**One process, the vulnerability matcher, reads both streams alone, waits until
each store's owner has stored what a batch is about, decides every asset the
batch names against that asset's previous decisions, and publishes decisions
that a writer of their own keeps, one row per episode of exposure.**

### A finding is named by its asset, its item and its CVE

A finding is `(tenant, agent, item, vulnerability)`. The item is named by
`inventory.ItemIDs` (ADR 43), so a package that gains a sibling gets a new name:
its open findings close as `REMOVED` and open again under the new one, each
carrying the package and version for a reader to relate them. The vulnerability
is the CVE among an advisory's `aliases` and `upstream`, or the advisory's own id
where it names none. One CVE told by a DSA, a DLA and `DEBIAN-CVE-*` is therefore
one finding, judged by all three together: the gravest reading stands
(`vulnerability.Judge`), and the finding cites every one of them at the version
it read.

### The matcher reads the stores, and waits for their owners

`cmd/vulnerability-matcher` consumes `security.inventory.raw` and
`security.advisories` in one group and one loop (`ConsumerConfig.Topics`). It
reads ClickHouse through `clickhouse.MatchingReader`, which holds no insert
statement, over a credential of its own that a deployment grants reads alone
(development Compose reuses the stores' user), and it produces to
`security.findings` alone. `finding-writer` keeps what it publishes. Nothing the
matcher decides reaches a store any other way, and no package of it can name a
feed, an HTTP client, a capability that writes a store or `internal/alert`
(`tests/architecture`).

Before it decides a batch it **settles**:

- `inventory-projector` must have committed past every inventory record in the
  batch, and `advisory-writer` past every advisory record. An owner commits only
  once its batch is durable, so a committed offset past a record means the record
  is in the owner's store.
- `finding-writer` must have committed up to where `security.findings` ends at
  that moment. That covers the matcher's own last batch, a restart, and a replica
  that published after it lost its partitions.

That answers the first problem. For an inventory record `r` and an advisory `a`,
the evaluation triggered by `r` runs after `r` is stored and reads the advisory
store; the one triggered by `a` runs after `a` is stored and reads the inventory.
If the first ran before `a` was stored, the second runs after `a` was stored,
hence after `r` was, and sees both: every pair meets in at least one evaluation.
That needs a store that reads its own writes, which a single ClickHouse with
synchronous inserts does; a replicated one (BE-087) needs quorum inserts and
sequential consistency on these reads. An owner that stops is lag the matcher
waits out, logged once a wait passes thirty seconds and measured per owner. It
is never a decision made without it.

An inventory record of packages or of the operating system names an asset to
assess **whole**; other kinds are ignored. The asset is read from the store, not
from the record, through ADR 27's rule for what is current. An advisory record
names the `(ecosystem, package)` keys of its new version and of the version
before it, read from the store, so a version that stopped naming a package still
reaches the assets holding it. Holders are found in `asset_package_holders`
(below); an asset the batch assesses whole is not assessed again by its packages,
and a holder in another ecosystem is not assessed at all.

### One reader, verified

A second matcher would be the third problem, so the matcher's group must hold
every partition of both topics in one member, or none. That is
[ADR 23](0023-state-is-owned-by-the-partition-and-rebuilt-by-reading-it-back.md)'s
sole reader, verified the same way and never assumed: `broker.Ownership` is asked on
every assignment and revocation, and a member holding part of the topics stops.
A refusal now cancels the poll in progress, so a refused member stops even when
nothing arrives. Before, a reader refused while it waited in `PollRecords` kept
waiting until a record came, and that held for the analysis engine too. Records
returned by the same poll as a refusal are never delivered. A second replica
therefore makes both stop: an explicit outage, as ADR 23 prefers to a quietly
wrong answer. Scaling past one reader means co-partitioning the advisory trigger
by agent onto the inventory's partitions, which waits for a measurement.

### Labels against the newest decision, and a whole assessment re-lists

`finding.Assess` and `finding.AssessPackages` are pure: an asset, the newest
intelligence for its ecosystem, the asset's newest decision for each finding,
the instant of the read and a policy go in; decisions and the `Assessment` they
were made in come out. Against the newest decision of a finding:

| Now | Before | Decided |
|---|---|---|
| affected | nothing, or never open | `AFFECTED`, `opened_at` = the inventory instant |
| affected | open | the same label, the same `opened_at` |
| affected | closed | `REINTRODUCED`, `opened_at` = the inventory instant |
| past the fix of the span it was in | open | `FIXED`, with that fix |
| no advisory calls it affected any more | open | `NOT_AFFECTED` |
| the package is gone from the newest scan | open | `REMOVED` |
| cannot assess | open | `CANNOT_ASSESS`, still open, with the episode's `opened_at` |

A closing carries the `opened_at` of the episode it closes. `opened_at` is the
inventory instant rather than the clock, so deciding again from the same
inventory lands on the same instant. Because the past read back includes a
replay's own earlier decisions, labelling is built as a fixed point: deciding
again from the same stores decides the same findings, which a test holds.

A **whole** assessment decides every open and cannot-assess finding of the asset
again, at the new instants. That is the line the contract describes: a reader
holds an asset's open findings to its newest whole assessment, so a finding the
newest whole assessment did not list is not open, explicit closing or not. A
**partial** assessment judges only the packages an advisory names, closes nothing
for being absent, and publishes nothing when it decided nothing. Each asset's
findings are published before its assessment, on the agent's partition.

### A gap is never an answer

- No operating system yet, a distribution or a release no feed is read for, or a
  feed the platform never read whole: the asset is unassessed for that reason,
  and its findings stand as they were.
- A package that cannot be judged (a foreign manager, no name, no version, an rpm
  version whose source lends no epoch, a version its manager would not write) is
  counted by reason in the assessment. Its open findings become `CANNOT_ASSESS`
  with that reason and stay open.
- An advisory boundary nobody can order, or a range not stated in the ecosystem's
  versions, is `CANNOT_ASSESS`. It closes nothing.
- **Stale intelligence resolves nothing.** A feed whose last complete reading is
  older than the freshness bound (48 h by default) is stale. The bound is measured
  from the inventory instant and never from the clock, so a replay is as fresh as
  the first decision. A stale assessment raises what it finds affected, closes
  nothing and says it was stale; readers do not hold an asset to it. A feed read
  by more than one source is as fresh as the stalest of them.

### The rating shown is one an advisory asserted

Nothing is scored here. Policy 1 picks, among the ratings of every advisory
citing a finding: one given for the package before one given for the whole
advisory; the publishing database's own before another assessor's; the
distribution's scale before CVSS, and a newer CVSS before an older; then
advisories in the order of their names. `Rating` records the advisory, whether
the rating was for the package, and the policy, because the choice is the
platform's.

### Storage follows ADR 12's method

Decisions are computed, analytical and replayable, so they live in ClickHouse,
written by `finding-writer` from `security.findings`, validated against the
contract and quarantined when they break it.
[ADR 12](0012-storage-is-owned-per-workload.md) left findings as an open class;
this closes it.

- `vulnerability_findings` keeps **one row per episode**, ordered by
  `(tenant_id, agent_id, item_id, vulnerability_id, opened_at, state)` and
  versioned by `decided_at`. Deciding an open finding again replaces its row;
  a fix, a removal and a reintroduction are rows of their own. That answers the
  fourth problem: storage grows with the history a reader asks for, not with the
  number of scans. `decided_at` is the instant the matcher read the stores, which
  orders decisions as their inventory and intelligence do, because those stores
  only grow; a late decision never replaces a newer one. A TTL of a year on
  `decided_at` is never reached by an open finding of an asset that still reports.
- `vulnerability_assessments` keeps one row per evaluation, keyed by the asset,
  its scope and both instants.

Both keep the record exactly as the matcher published it, beside the columns an
estate is asked about, as `agent_assessments` does. Dispositions belong to people
and are relational, so they go to PostgreSQL through `control-api`, which is a
change of its own: a disposition never changes or hides a decision.

### Which assets hold a package is a table of the inventory store

ADR 27 left the reverse lookup to this card and ruled out a `PROJECTION` under
`FINAL`. `asset_package_holders` is written by `inventory-projector` in the same
batch as the package rows, one row per name a distribution's advisories may give
a package (`vulnerability.PackageNames`: the source for Debian, Ubuntu, Alpine and
Rocky Linux, the binary for AlmaLinux), because a package is stored before its
asset's distribution is known. It says where to look and never what is there;
whether the asset still has the package is read from `asset_inventory`.

## What this deliberately does not do

- **No second reader.** Co-partitioning is the way to scale, and it waits for a
  measurement of a real estate.
- **No re-evaluation when a stale feed recovers.** The next inventory record of
  each asset (agents send one a day) decides it again.
- **No read plane.** Listing findings by asset, by CVE and by state is BE-061.
- **No dispositions yet.** People's decisions about findings are their own change.
- **Not exactly once.** A replica that published after it lost its partitions can
  have labelled against a past missing what the next reader decided. That is one
  batch at most: the next whole assessment lists the asset's open findings again,
  so what is open is right again, and a label it got wrong stays in that
  episode's history.
- **An episode that passed through `CANNOT_ASSESS` is labelled `AFFECTED` when it
  is affected again**, `REINTRODUCED` or not before: a cannot-assess decision
  carries the episode's `opened_at` but not its label.

## Consequences

- Two topics, two processes and three tables more: `security.findings` and its
  quarantine, `vulnerability-matcher` and `finding-writer`, and
  `asset_package_holders`, `vulnerability_findings`, `vulnerability_assessments`.
- The matcher's lag is how far behind findings are; each owner's lag adds to it,
  and the settle histogram says which owner the matcher is waiting on.
- A new matcher group reads both topics from their start: every asset that sent
  inventory within the topic's retention, and every advisory the compacted topic
  holds. The first import of a large feed through the advisory trigger is the
  matcher's heaviest work, and it is measured before it is trusted.
- `broker.Consumer` reads several topics in one group and asks a reader what it
  may hold, which is how the analysis engine's sole reader stops too.
