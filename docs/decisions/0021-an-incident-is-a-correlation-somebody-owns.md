# 21. An incident is a correlation somebody owns, and how far its order can be trusted is measured

## Context

[ADR 11](0011-a-detection-is-not-an-alert.md) said what a detection is by saying
what it is not, and [ADR 16](0016-an-alert-is-a-detection-somebody-owns.md) did
the same one level up and ended by naming the thing it was not: *an alert is not
an incident. Correlation output will produce something that groups alerts, and it
will be named by what produced it in the same way.*
[ADR 20](0020-a-sequence-is-decided-by-the-window-that-holds-it.md) then built the
correlation — a rule whose stages are ordered in event time, naming one event per
stage, carrying how far the clocks that ordered them stood apart.

BE-023 is the card that finishes the four concepts, and it arrives with the
collapse it exists to prevent **already in the tree**: `alert-writer` reads every
detection on `security.detections` and raises an alert for anything above its
floor, so a sequence detection becomes an ordinary alert. A story several events
tell and a finding about one event would share a table, a key, a fold and a list,
and the only thing separating them would be the rule that happened to make each.

v1 is more useful here than usual, because on the central question **it was
right**: `correlation_incidents` is a table of its own, and
`correlation_incident_evidence` beside it names an alert or an event per stage.
What went wrong is elsewhere, in three places worth carrying:

- **the lifecycle is a fourth vocabulary.** `open|triaged|closed|suppressed` on
  the incident, beside `status` and `disposition` on the alert. Two triage
  languages for one act, and neither is the other's subset;
- **`confidence` is an invented number.** `min(99, 62 + min(30, len(stages) * 8))`
  in the sequence engine, `min(99, 55 + min(35, len(selected) * 4))` in the
  threshold one, `min(99, 58 + min(34, distinct_count * 5))` in cardinality,
  `74 if reason == "first_seen" else 80` in entity state. Five engines, five
  formulas, one 0–100 scale, and nothing behind a single constant. A number that
  precise claims the platform measured something, and nothing was measured;
- **`dedup_key` is indexed and not unique**, so what stops one story being told
  twice is a query and a convention rather than the key.

## Decision

**An incident is what a correlation becomes when a person has to answer for it,
and it is named by that correlation detection.** `incident_id` *is* the detection
id, exactly as an alert's is, so re-deciding the same events against the same rule
finds the incident that already exists. ADR 20 already tells a story once per
window that holds it; naming it after the detection is what makes that hold
across a replay as well.

**A detection that carries a correlation becomes an incident and never an alert.**
One finding, one piece of work. This is the whole card in one sentence: the two
records are told apart by what the analysis engine put in them rather than by
which list somebody happens to read, and `internal/incident` does not import
`internal/alert` — an architecture test refuses it, in both directions.

**The floor and the suppressions still apply; the fold does not.** A story below
the severity a person's time is worth is not work, and an estate that has
silenced a rule has silenced it. But an incident is not folded into an open one,
is not held back by a cooldown and carries no correlation key: ADR 17 put the
fold there to remove repetition from the alert plane, and ADR 20 already decided a
story is told once per window. A second dedup on top of one that exists would be
two answers to one question.

**It is opened by `alert-writer` and by no new process.** ADR 16 earned that
process a failure domain of its own — a relational store nobody can reach stops
alerts being opened and does not stop detections being stored. Incidents share
that store, that volume and that failure, so a third consumer of
`security.detections` would add a consumer group, an image and a Compose service
without adding a failure domain. The process is named for the plane it writes to
and not for the one kind of record it used to write.

**Confidence is measured, closed, and the platform's rather than the rule
author's.** Severity says how much a story would matter if it happened in that
order; confidence says how far the data supports that order at all. It is decided
from what ADR 20 already carries — the clock spread against the story's own span,
and against the window the rule asked to look through:

```text
spread < span      the clocks order the story themselves          high
span <= spread < window   the events belong together and their order does not follow   medium
window <= spread   nothing in the data supports either            low
```

Three levels because the platform can distinguish three, and no more: the yardstick
is the one the rule author already chose when they wrote the window, so nothing
here is a constant somebody tuned. `high` is exactly ADR 20's ordering test read
as a word. A rule cannot declare its own confidence, because a rule cannot know
how well the clocks of an estate agree.

**Its lifecycle is the same five states, declared separately.** Triage is triage:
somebody acknowledges a story, investigates it, resolves it or finds it was not
one, and a second vocabulary for that is v1's mistake rather than a distinction.
But the states are declared in `seagull.incident.v1` and the machine is
`internal/incident`'s own, because an incident is not an alert and the first time
a story needs a state a piece of work does not, neither should have to ask the
other. Closing a story as a false positive requires its reason for the reason ADR
16 gave: it is the only signal the author of a *correlation* rule gets that the
stages or the window are wrong.

**What an incident is made of is on the record.** It names the detection that
told it, one event per stage in the order the rule declares them, and the group
that made those events one story — an address, a host, an account. That is the
trace the card asks for, and it is two hops rather than a join: the incident names
the events, and the detection it names carries the evidence they were decided on.
Nothing an operator does to an incident writes to any of them; the store's update
touches the operational columns and never the stages.

## Consequences

- **An incident does not group the alerts of its component events, and this is
  deliberate.** The correlation names events; the alert plane indexes detections.
  Linking the two means keeping an index from events to alerts in the operational
  store, which is a second source of truth about which alerts are about which
  events and deserves its own card and its own evidence. What the card asked for —
  tracing an incident to events and detections — is answered without it, and the
  contract and the schema both take the link additively when somebody wants it.
- **PostgreSQL grew a second workload and no second store.** `0003_incidents.sql`
  adds `incidents` and `incident_transitions`. The stages and the group are
  parallel arrays on the row rather than child tables, the way the detection store
  holds the same data in ClickHouse: they are bounded by the stages a rule may
  declare, always read with the row, and a `cardinality` check refuses a row whose
  arrays disagree.
- **`incidents` is a resource in the policy**, with its own read, write and
  delete. A caller who may work alerts is not thereby able to close the story that
  grouped them, and reaching past somebody else's incident needs `incidents:delete`
  exactly as reaching past their alert needs `alerts:delete`. Every existing policy
  denies all three until an estate grants them, which is the fail-closed direction.
- **Two ports where there was one.** `alertstore` names a `Sink` and a `Stories`,
  and the batch is written to each in turn. Both are idempotent on the detection
  that produced them, so a batch that half succeeds is retried whole and finds what
  it already wrote; the group position advances only when both are durable.
- **A story below the floor is stored as a detection and is nobody's work**,
  unchanged from ADR 17 — noise is removed from the operational plane and never
  from the detection stream. The shipped sequence rule is `critical`, so the
  default floor never hides one.
- **Nothing produces a `low` confidence in the local stack.** The shipped rule
  groups by `origin.agent_id`, so one clock times every event of a story and the
  spread is transit; reaching `low` needs an estate whose agents disagree by more
  than five minutes. The level exists because such an estate exists, and the
  integration suite is where all three are proven.
