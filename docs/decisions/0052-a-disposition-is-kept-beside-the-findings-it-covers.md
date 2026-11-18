# 52. A disposition is kept beside the findings it covers: it always expires, ends early only by a withdrawal written beside it, and nothing that decides a finding reads it

## Context

[ADR 49](0049-a-finding-is-decided-by-one-reader-from-the-stores-their-owners-filled.md)
keeps what the platform decided about vulnerabilities in ClickHouse, computed and
replayable, and left what people decide about them to a change of its own:
person-owned and relational, so PostgreSQL through `control-api`, and never a
change to a decision.

The contract (`v0.22.0`) says what that change keeps. A disposition is IGNORED,
the finding does not apply as the platform reads it, or ACCEPTED_RISK, it applies
and somebody chose to live with it. It covers one vulnerability on every asset of
its tenant, narrowed to one agent and to one package when those are named. A
request carries a reason and an expiry, both required; the actor is whoever
proved who they are on the connection. A disposition always expires and ends
early only by being withdrawn, and both are new facts rather than its removal.
The card's criterion is the same: accepted risk and ignored are auditable
mutations, never deletions.

V1 kept a disposition as `operator_disposition`, a column of the finding row,
patched in place with no reason, no actor and no expiry. The same patch could
overwrite what the platform had observed, nothing said who had decided or when,
and a suppressed finding stayed suppressed for good.

Nathan decided who may act on 2026-11-08: `vulnerabilities:write` for the
responder and the administrator, as for `alerts:write`, and `vulnerabilities:read`
for the analyst, the responder and the administrator.

## Decision

**A disposition is a record of the control plane, written once by `control-api`
into PostgreSQL beside the findings it covers. A withdrawal is a second record
written beside it. Nothing that decides or keeps a finding can name either.**

### What a disposition holds

`internal/disposition` decides a disposition from a request, the subject the
guard verified and the listener's clock, and the request can name neither of the
last two:

- the tenant, a tenant identifier, and the vulnerability, as an advisory names one
  (`vulnerability.Identifier`), both required;
- the agent, when named, one its tenant registered, in any state; checked by the
  statement that records the disposition, so a typed name that covers nothing is
  refused with `disposition_names_unregistered_agent`;
- the package, when named, as the asset names it: inventory's bound on a name and
  no control character;
- a reason of at most 1,024 bytes holding something besides blanks and no control
  character but a tab or a line break, so a NUL never reaches PostgreSQL and an
  escape sequence never reaches whoever reads the reason in a terminal; a
  withdrawal's reason is held to the same;
- an expiry after the moment it is recorded and at most 365 days later. One that
  lasts longer hides a vulnerability for as long as nobody looks.

The vulnerability and the package are not checked against any finding or
inventory: a person may decide before a finding names them, and `control-api`
reads no analytical store for it. A disposition is named by a random identifier
the platform draws, written the one way it is drawn, and its instants are kept to
the microsecond, so what a caller is answered is what the store holds.

### How it is kept

Migration `0011` adds `vulnerability_dispositions` and
`vulnerability_disposition_withdrawals`. The adapter writes both by INSERT and
holds no UPDATE or DELETE for either. The withdrawal is keyed by the disposition,
so two people withdrawing one at once are one withdrawal and one `409
disposition_lapsed`. A disposition is withdrawn only while it is in force: not
withdrawn, and expiring after the moment the request arrives.

### Who may do what

`vulnerabilities:read`, `:write` and `:delete` are a tenant's
([ADR 50](0050-a-grant-reaches-the-platform-or-the-tenants-it-names.md)).

| Route | Needs | Answers |
|---|---|---|
| `POST /v1/vulnerabilities/dispositions` | `vulnerabilities:write` in the tenant it names | `201` with the `Disposition` |
| `POST /v1/vulnerabilities/dispositions/search` | `vulnerabilities:read` | a `DispositionPage` within the caller's tenants |
| `POST /v1/vulnerabilities/dispositions/{id}/withdrawal` | `vulnerabilities:write` | `200` with the `Disposition` and its withdrawal |

The tenant a request names is decided by the policy before anything is read, as
an agent's registration is ([ADR 14](0014-a-token-says-who-and-the-policy-says-what.md)).
The store is asked within the tenants of the caller's grant and never within one
a cursor carries, and a disposition outside them is `404` like one never
recorded.

The shipped policy follows Nathan's decision. The tenant administrator, written
after it ([ADR 50](0050-a-grant-reaches-the-platform-or-the-tenants-it-names.md)),
holds `alerts:write` and so holds `vulnerabilities:write` too. Nobody holds
`vulnerabilities:delete`: no route asks for it, and nothing is deleted.

### How it is read

Newest first by when it was decided, then by its identifier; 50 a page unless
asked, 500 at most; the cursor holds both, the instant to the microsecond, since a
coarser one would skip whatever was decided within the same millisecond.
Lapsed dispositions, expired or withdrawn at the listener's instant, are left out
unless `lapsed` asks for them. `agent_ids` is answered with every disposition
covering one of the agents: its own, and those of its tenant naming no agent,
which is what somebody looking at one asset asks. `vulnerability_ids` and `kinds`
match as written, and a kind the contract does not declare is refused with
`unknown_filter`.

### Never read by what decides a finding

`tests/architecture` refuses `internal/disposition` to `internal/finding`,
`internal/matching` and `internal/findingstore`. The matcher goes on deciding as
it reads, a finding someone accepted stays open while it is affected, and a reader
holds the two side by side.

### What is observed

`seagull_control_vulnerability_dispositions_total{outcome}` counts `ignored`,
`accepted_risk`, `withdrawn` and `refused`. `vulnerability_disposition_recorded`
and `vulnerability_disposition_withdrawn` log the identifiers, the kind, the
expiry and the actor, never a reason, beside the guard's `control_request_allowed`.

## What this deliberately does not do

- **No idempotency key.** A request retried after its answer was lost records a
  second disposition; both are listed and either is withdrawn.
- **No findings read with their dispositions applied.** Showing them together is
  the read plane's (BE-061) and the frontend's.
- **No notice before an expiry and no renewal.** A disposition that should go on
  is recorded again.
- **No quota.** A caller holding `vulnerabilities:write` is rate-limited as every
  operator is.
- **No retention.** Dispositions are kept as alert trails are, until BE-089
  decides how long a person's name is kept.
- **No audit log of its own.** The record names who decided what, why and until
  when, and who ended it; BE-039 carries that into the platform's audit log.

## Consequences

- `control-api` answers `503 dispositions_unavailable` when the control store
  does not, and nothing is recorded; it refuses to start on a store without the
  two tables.
- `control-migrator` applies `0011`.
- The matcher, `finding-writer` and the findings tables do not change.
