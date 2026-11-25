# 59. The read plane lists what an asset has and what is wrong with it, within the scope a hunt is answered in, and what an asset currently has is written once

## Context

Nothing read inventory, advisories or findings back for a person.
[ADR 27](0027-inventory-is-a-record-kind-of-its-own.md) left the read route to
"BE-036 and the query plane", and the definition of what an asset currently has
lived in the integration suite. [ADR 43](0043-a-record-keeps-apart-what-one-identity-would-fold.md)
left to BE-061 how an asset's instances are read back.
[ADR 49](0049-a-finding-is-decided-by-one-reader-from-the-stores-their-owners-filled.md)
decided findings and kept them, one row per episode, and said that a reader holds
an asset's open findings to its newest whole assessment. Contracts `v0.22.0`
already declare the questions and their pages — `AssetQuery`, `ItemQuery`,
`AdvisoryQuery`, `FindingQuery`, `FindingHistoryQuery`, `AssessmentQuery` — and
`control.v1.Resource` `INVENTORY`.

"Current" was written three times and two of them disagreed on a kind no full
enumeration ever reached: the suite's query and the contract's comment on `Asset`
read nothing of it as current, and the matcher read every item of it as current.
Only a delta reaches that state and nothing sends one, so nothing observable
depended on the difference yet.

## Decision

**`query-api` answers six listings beside its two hunts, through the same
admission, the same scope and the same budget, and what an asset currently has
is one condition the matcher and the read plane both ask the store through.**

### A listing is a question of the read plane

| Route | Question | Page | Permission |
| --- | --- | --- | --- |
| `POST /v1/inventory/assets` | `AssetQuery` | `AssetPage` | `inventory:read` |
| `POST /v1/inventory/items` | `ItemQuery` | `ItemPage` | `inventory:read` |
| `POST /v1/vulnerabilities/findings` | `FindingQuery` | `FindingPage` | `vulnerabilities:read` |
| `POST /v1/vulnerabilities/findings/history` | `FindingHistoryQuery` | `FindingPage` | `vulnerabilities:read` |
| `POST /v1/vulnerabilities/assessments` | `AssessmentQuery` | `AssessmentPage` | `vulnerabilities:read` |
| `POST /v1/vulnerabilities/advisories` | `AdvisoryQuery` | `AdvisoryPage` | `vulnerabilities:read` |

They live in `internal/hunt`, the read plane's one capability, rather than in a
capability of their own, because what they share is the plane: the caller named
by its certificate's subject, the policy pinned at startup, the tenants of the
grant as the only scope, the per-caller limiter, the process-wide ceiling, the
signed cursor and the read budget. A second capability could not name the first's
and would have kept a second ceiling a process holds questions to. A refusal is a
`seagull.hunt.v1.Refusal` on every route.

`inventory` is a resource of its own, with the tenant's scope its telemetry has,
and `control-api` shows it as `RESOURCE_INVENTORY`. An advisory is intelligence,
not a tenant's: it is read under `vulnerabilities:read`, the permission that reads
what cites it, by a caller holding it in at least one tenant.

A listing has no window: it is asked of the state the platform holds now, by the
key that state is sorted by. Its limits are the plane's — at most 256 values to a
filter, 512 bytes to a value, the page and its ceiling, the read budget as a
deadline and as `max_execution_time` and `max_rows_to_read`. Its cursor is a
position only the store can name — an asset's tenant and agent, a package's name
and version — which the plane signs with everything that decides the page, in a
layout of its own, so a hunt's cursor is never read as a listing's, page two of
one question cannot be spent on another, and a page is followed by a cursor
whenever it carried anything, as a hunt's is.

### What an asset currently has is written once

An item is current when it was last seen at or after the newest full enumeration
of its kind, **and every item of a kind never enumerated in full is current.**
That is the matcher's reading, and it is kept because the other one turns a gap
into an answer: `finding.Assess` closes as `REMOVED` every open finding whose item
is not current, so a kind nobody enumerated read as empty would close findings no
enumeration ever retired, and report what a delta named for too short a time
rather than too long, against ADR 43. It is one condition in
`internal/clickhouse`, which the matcher and the read plane both ask, and the
integration suite asks the read plane instead of a query of its own.

### One instance is one entry

Two current rows can say the same thing after a delta (ADR 43), so an item
listing groups rows by what tells two instances apart — a package's name,
version, architecture and manager; an account's uid and name; a service's or an
interface's name; a process's pid and start; the identity of a kind that holds one
— and answers the newest row of each. Without a name it lists what the asset holds
now, against the enumeration the page names; with one it lists every instance of
that name the asset was seen with, newest first, each saying whether it still
is, which is as much of a package's history as a store that replaces a row on
upgrade keeps.

### An asset is listed by its enumerations

Assets are paged from `asset_inventory_scans`, a row per kind per asset, and
only the page's assets are read in `asset_inventory`, for the host the newest
record named and when anything on them was last seen. `scanned_before` keeps an
asset with a kind last enumerated before it, which is how a stale inventory is
found. An asset known only from deltas has no enumeration and is not listed; its
items are read by its agent. Paging the item table for distinct assets would read
every process row an asset ever reported to answer a page of names.

### A finding is listed where it stands

Each finding is listed as its newest decision, ordered by `inventory.as_of`,
`intelligence.as_of` and `decided_at` as the contract orders them, and held to
the asset's newest whole assessment made on fresh intelligence of an asset that
could be assessed: an open decision older than it is a finding that assessment
did not list, and is left out rather than shown open or shown with a closing
nobody decided. A stale assessment and one that could not assess the asset hold
nothing back. A history is every episode of one finding, newest first; an
assessment listing is the newest whole assessment of each asset, stale or not,
since that is what says why a finding was not decided again. Filters on states
apply to where a finding stands.

### An advisory is read as it was read

By name, every version of one advisory, newest first, so what a finding cites
stays readable after the source moved on; by package, the newest version of every
advisory whose newest version names it. A withdrawal is a newer version, so an
advisory whose newest version withdrew it is left out unless asked for, never
answered by the versions before it. What is read back is the contract message:
`advisorystore.Restore` and `inventorystore.Restore` are the inverses of the
projections beside them, and the round trip is a test.

## What this deliberately does not do

**No inventory read in `control-api`.** It reads an agent's status, posture and
findings about the agent (ADR 30, 33, 56), and nothing of what an asset has.

**No disposition in a finding listing.** What people decide is `control-api`'s,
in PostgreSQL (ADR 52); the read plane holds no relational connection.

**No aggregation and no free text.** How many assets hold a package is a different
shape of answer, as ADR 13 says of a hunt.

**No index for a finding asked by CVE across an estate.** It is read within the
caller's tenants under the budget; a skipping index waits for a measurement.

## Consequences

- [ADR 13](0013-a-query-is-a-scope-a-window-and-a-question.md) is amended: the
  read plane also lists, with a scope and a question and no window, and its store
  connection is one of the analytical store's readers, `control-api`'s being
  another since ADR 30.
- [ADR 27](0027-inventory-is-a-record-kind-of-its-own.md) is amended: the read
  route exists, and a kind never enumerated in full is current.
- [ADR 43](0043-a-record-keeps-apart-what-one-identity-would-fold.md) is
  amended: a reader lists instances, grouped by what tells them apart.
- [ADR 47](0047-the-query-plane-decides-by-the-policy-and-a-certificate-organisation-authorises-nothing.md)
  is amended: `inventory:read` and `vulnerabilities:read` authorise the listings
  as `events:read` and `detections:read` authorise the hunts.
- The contract's comments on `Asset` and `HeldItem.current` say a kind never
  enumerated in full has nothing current; they are owed a comment patch with the
  next contracts release, which changes nothing on the wire.
- Every deployment grants `inventory:read` to whoever reads what assets have; the
  development policy grants it to every role that reads vulnerabilities.
- Built by the session that wrote this, for Nathan to overrule: the routes in
  `internal/hunt`, an advisory read under `vulnerabilities:read`, a never-enumerated
  kind read as current, and an asset listed only once a kind of it was enumerated.
