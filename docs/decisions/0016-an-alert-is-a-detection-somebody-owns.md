# 16. An alert is a detection somebody owns

## Context

[ADR 11](0011-a-detection-is-not-an-alert.md) said what a detection is by saying
what it is not: no status, no assignee, no disposition, because those belong to
an alert with a lifecycle and an owner. [ADR 12](0012-storage-is-owned-per-workload.md)
then classified alerts as low volume, mutable, relational and person-owned,
named PostgreSQL as the answer, and refused to create it — *because none has a
producer*.

BE-030 is the producer arriving, and it brings three questions ADR 12 left open.

**What raises an alert?** v1 answered it by having one table, so every detection
was an alert and an operator's queue was the detection stream. That is why v1's
alerts table carried `status`, `assigned_to` and `triage_notes` in the same row
as the ATT&CK attribution — and why a reprocessed batch could step on somebody's
triage.

**Where does it live?** The two analytical tables are `ReplacingMergeTree`s
ordered by content, which is exactly right for a record that is rewritten by a
replay and exactly wrong for a row that says *this is assigned to somebody and
only they may close it*.

**Who may move it?** [ADR 14](0014-a-token-says-who-and-the-policy-says-what.md)
resolves a grant per request and carries tenants on it, while
[ADR 13](0013-a-query-is-a-scope-a-window-and-a-question.md)'s `hunt.Scope`
reads tenants off the certificate. Both were written down as a gap for whichever
card first had the control plane answer a question about stored records.

## Decision

**An alert is what a detection becomes when a person has to answer for it, and
it is named by that detection.** One alert per detection, structurally: the
primary key *is* the detection id, so re-deciding the same events against the
same rule finds the alert that already exists. Replay safety is a property of
the key rather than a rule somebody has to remember.

**The two halves have different owners and are written by different processes.**
The analytical half — rule, revision, severity, technique, class, agent, tenant,
event time — is copied out of the detection when the alert is raised and never
written again. The operational half — state, assignee, closure, revision — is
only ever written by the control plane. `cmd/alert-writer` inserts and never
updates; `cmd/control-api` updates and never inserts. A replayed detection is an
`ON CONFLICT DO NOTHING`, so nothing the analytical stream does can reach
somebody's triage.

**Severity decides what becomes work.** `alert-writer` raises an alert for a
detection at or above a floor it is pinned to, default `medium`. The detection
contract already says a consumer routes on severity, and this is that consumer.
A detection below the floor is still stored, still queryable and still part of a
hunt; it is just not somebody's work. The floor is a setting rather than a
constant, because it is the one product decision this process makes.

**The lifecycle is a table, and it is closed.**

```text
open ─┬─▶ acknowledged ─┬─▶ in investigation ─┬─▶ resolved ───────┬─▶ open
      │                 │                     │                   │
      └─────────────────┴─────────────────────┴─▶ false positive ─┘
```

Triage runs forwards, and the only way back is out of an ending — to `open`, not
to the middle: an alert somebody reopens has not been acknowledged again. A move
to the state an alert is already in is refused rather than recorded, because a
line of trail that says nothing is worse than no line.

**`resolved` and `false positive` are different acts, and the difference is
structural.** Closing as a false positive *requires* a reason, and so does
reopening; resolving does not. Both of the first two say an earlier decision was
wrong, and the false-positive reason is the only signal a rule author gets that a
rule needs correcting — v1 had the field and nothing required it, so it was
usually empty.

**Every move is attributable, and the trail is append-only.** One row per
revision in `alert_transitions`, carrying from, to, assignee, actor, instant and
note, written in the same transaction as the alert it describes. An assignment
writes a line too: handing work over changes nothing about triage and is still
something somebody is accountable for.

**Authority is decided in three parts.** The route requires `alerts:read` or
`alerts:write`, as every route does. The alert is then read *within the tenants
the grant carries* — which is where the query plane's tenancy and the control
plane's finally meet, on the policy's side. And an alert **assigned to somebody
else** needs `alerts:delete` on top, exactly as ending another caller's session
does: `delete` is this policy's verb for reaching past what is yours.

**Two people acting at once means the second is told.** Every move carries the
revision it was decided against — the caller's if they sent one, otherwise the
one the authority decision was made on — and the store applies it under `SELECT
… FOR UPDATE`. A stale revision is a `409`, not a silent overwrite.

## Consequences

- **PostgreSQL exists.** It is the first relational store in v2 and the workload
  ADR 12 named it for. `internal/postgres` is an adapter, `cmd/alert-migrator`
  applies its schema by command as `store-migrator` does ClickHouse's, and every
  process that reads it verifies the schema before it serves. Migrations run one
  per transaction, so an interrupted run is before or after and never half-way —
  which is what lets the statements be ordinary rather than idempotent.
- **A ninth component and a sixth long-running process.** `alert-writer` is a
  second consumer of `security.detections` in a group of its own. It earns that
  the way `detection-writer` did: its own failure domain and its own lag, so a
  relational store nobody can reach stops alerts being opened and does not stop
  detections being stored.
- **It quarantines nothing.** `detection-writer` consumes the same topic and
  already writes exactly the records `alert-writer` cannot use to its
  quarantine, verbatim. A second copy from a second consumer would double every
  poison record without saying anything new; this one steps over what it cannot
  use and counts it by reason.
- **The state machine is a pure function, and the store only makes it atomic.**
  `alert.Apply` decides legality, the reason requirement and the revision, and
  returns the next alert and the line of trail. `internal/postgres` calls it
  inside a transaction and `internal/control` calls nothing else. The listener
  therefore cannot allow a move the store would refuse, and neither can a
  future caller of the same domain.
- **The alert plane is the control plane, not the query plane.** Reading an
  alert and acting on one are the same workflow, the store is different, and
  ADR 13's read plane stays what it is: the only reader of the analytical
  tables. `query-api` gains nothing here.
- **`hunt.Scope` still reads the certificate.** Alerts are scoped from the
  grant, so the control plane now answers about stored records using the policy;
  the query plane does not, because it holds no policy. Closing that fully means
  `query-api` resolving a grant, which is a change to the read plane rather than
  to this card.
- **An alert is not an incident.** Correlation output (BE-023) will produce
  something that groups alerts, and it will be named by what produced it in the
  same way. Nothing here assumes one alert per detection forever; it assumes an
  alert is named by the analytical record it is about.
