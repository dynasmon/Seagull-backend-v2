# 20. A sequence is a rule whose stages are ordered in event time, decided once per window that holds it

## Context

[ADR 19](0019-a-rule-that-counts-decides-on-a-window.md) made a count part of a
rule rather than a second kind of rule, and left two things behind on purpose:
the ordered window read back, which [ADR 18](0018-detection-state-is-a-bounded-window.md)
named and deliberately did not expose, and `Observation.Value`, which ADR 18
described as holding "which stage of a sequence the event satisfied" and which
nothing filled. BE-022 is the card that uses both, and its worked example is one
sentence:

```text
a failed SSH password, then one from the same address that was accepted, inside five minutes
```

v1 answers this with `features/correlations`: seven strategy engines behind a
facade — `sequence`, `chain`, `threshold`, `cardinality`, `entity_state`,
`risk_aggregation`, `temporal_join` — dispatched from a rule's `strategy` string
and run by a worker on a sixty-second cycle over the **alerts** table, capped at
five thousand rows inside a one-hour horizon. Five things follow from it, and
none of them is the sequence logic itself:

- **it correlates alerts, not events**, so a story can only be told about things
  that already became somebody's work, and the noise removal applied to alerts
  has already changed what there is to correlate;
- **a stage is a glob over `rule_id`** — `patterns: ["ssh_bruteforce_*"]` — which
  is the dictionary between a rule and a name that [ADR 6](0006-a-rule-addresses-the-contract.md)
  removed;
- **the same window is written in four places.** `window_seconds` on the rule,
  and `within_seconds`, `maxspan_seconds` and `min_count` per stage, each
  defaulting to another, free to disagree. It is `min_events` beside
  `condition.value` again;
- **time is `created_at`**, the row's insertion time, with `datetime.utcnow()` as
  the fallback — so ordering is processing time and a replay decides differently
  depending on when it runs;
- **there is no late-arrival or clock-skew handling at all.** Neither word
  appears in the feature. `segment_by_window` chains segments forward from the
  first alert, so two alerts a second apart land in different segments whenever
  the earlier one closes a segment, and the story between them is invisible.

## Decision

**A sequence is part of the rule, and a rule carries a sequence or a match and
never both, because the stages are what it matches with.** `detection.Sequence`
is named stages, a window and the fields that make two events part of the same
story. There is no `strategy:` discriminator and no second rule language: a stage
asks of one event exactly what a rule without a sequence asks of one event, and
everything else about the rule — its class, its severity, its cases, the route it
is registered on — is unchanged.

**The match of a stage is pure; the order is the part answered from state.**
`Program.Satisfied` reports which stages an event satisfies, from that event and
nothing else. Which stage comes after which is read out of the bounded window
ADR 18 built, and nowhere else. That is the same seam ADR 19 drew for a count,
and it is why neither card needed a second kind of rule.

**An event is folded under every stage it satisfies, and an event that satisfies
none is not folded at all.** Choosing one stage for an event that answers two
would make a sequence depend on which stage its author happened to write first.
An event no stage answers is not part of any story the rule tells, so it never
reaches the window and never costs it a slot — which is also what keeps a
sequence's state smaller than a count's on the same stream.

**The story is decided by the fold that made the window completable, whichever
stage that event satisfied.** The walk is greedy from the earliest: the first
observation satisfying the first stage, then the first after it satisfying the
second, and so on. Greedy finds an assignment whenever one exists, because a
later choice at any stage leaves no more of the window for the stages after it.
A detection is made when that walk completes now and would not have completed
without the event just folded.

**This is what "without depending on perfect arrival order" comes to, and it is
a property rather than a hope.** The walk reads a set of observations in event
time, and an observation lands where it happened rather than where it arrived,
so:

- **a story is found the same number of times however the backbone delivered
  it.** The test fires exactly on the transition from "no complete assignment"
  to "one exists", and that transition happens once per window whatever order
  the events reach it in;
- **a late event completes a story the platform could not see before.** A
  success that arrives before the failure it followed decides nothing; the
  failure, arriving after, is what completes it, and the detection carries the
  same name it would have carried had they arrived in order;
- **only the citation can differ.** Where several earlier events would each do,
  which one the story names depends on what was in the window at the moment it
  completed. Every one of them is a real event that really satisfied that stage,
  so the difference is which witness is quoted and never whether the story is
  true.

**A story is told once per window that holds it, and not once per event that
keeps it true.** This is where a sequence and a count differ, and deliberately:
a rule past its threshold decides again on every matching event (ADR 19), but a
second success inside the same window is the same compromise still going. Telling
it again per event would report a burst at whatever size an attacker chose. Once
the window has moved past the failure, the next failure and success are a new
story and are told afresh.

**A detection names one event per stage.** Naming the whole window is what ADR 19
refused for a count and the reason does not apply here: a sequence's events are
bounded by `MaxStages`, which the rule author declared, rather than by how much
an attacker sent. `Correlation` says which event satisfied which stage, so an
incident can be traced to its component events — which is what BE-023 needs and
could not get from a count.

**Clock skew is measured, carried and counted, never assumed away.** Ordering is
decided in event time, which is the producer's clock; the platform holds, for
every event, `observed_time` against the `ingest_time` the gateway wrote, and the
spread of that across the events of one story is how far apart the clocks that
ordered it stood. Events from one agent share a clock and spread by transit
alone. Events from two spread by whatever their clocks disagree about, which is
exactly what bounds how wrong the ordering can be. A story whose spread is wider
than its own span is one the data does not order: it is decided, it carries the
number, and it is counted under `sequences_unordered_total`.

**It is reported and not refused.** An estate with one badly-synchronised agent
would otherwise lose detections silently, which is the quietest way a detection
surface can be wrong; and the platform cannot tell a clock that is forty seconds
fast from an agent that uploads every forty seconds, so refusing would be
refusing on a number it cannot fully attribute. Over-reporting is the safe
direction: it never suppresses a finding, and `ordered` on the detection is what
an analyst reads before trusting the order.

**Nothing expires an incomplete sequence, because nothing has to.** A story half
told is the absence of a complete one inside a bounded window, and the window
forgets on its own: observations older than it are dropped as the window moves,
and keys the stream has passed are reclaimed under pressure by the watermark. No
timer, no goroutine, no expiry record — the same answer ADR 18 gave for a count,
reached again rather than reinvented.

**Restart is replay, unchanged.** The window is a pure function of the events
inside it, so there is nothing to checkpoint and nothing to restore; a store
narrowed below what a loaded rule asks for stops `analysis-engine` at startup,
now for `Bounds.Orders` as well as `Bounds.Admits`, because a key holding fewer
observations than a story has stages is a rule that would run and never fire.

**A stage set is one byte in the observation the store already holds.** The rule
language caps a sequence at `MaxStages`, eight, so the set an event satisfies
fits in the `Value` ADR 18 put there. A sequence therefore adds no field to the
state model and no second store.

## Consequences

- **A sequence's stages are all of one class.** A rule declares one class and is
  registered on one route, which is what keeps a rule out of the path of events
  it has nothing to say about. The card's third stage — privilege escalation —
  is not expressible because the contract declares one event class; when a second
  arrives, a cross-class sequence is a routing change and not a rule-language
  one, and it is named here so that the shape is chosen deliberately rather than
  discovered.
- **A sequence rule's cases prove which events are part of a story, not the
  story.** The same limit ADR 19 named for a count, for the same reason: what
  order makes a detection is the engine's and is proven once, in
  `internal/analysis`. `Program.Decide` on a sequence rule answers whether the
  event satisfies any stage, which is what makes a case meaningful and what the
  three cases on `ssh.password_guessing_that_succeeded` assert.
- **A story is cheaper to remember than a count.** Only events that satisfy a
  stage are folded, where a counting rule folds every event it matches. The
  shipped sequence rule holds two observations per address per five minutes; the
  shipped counting rule holds up to twenty per address per minute.
- **Two events at the same instant are ordered by which arrived first, and the
  detection says the order is not established.** A span of zero is never wider
  than a spread of zero or more, so `ordered` is false and the counter moves. It
  is the one case where arrival order reaches the citation, and it is reported
  rather than hidden.
- **`State.Distinct` is still unused.** Cardinality — thirty ports from one
  source — reads it, has no card, and is not smuggled in here. ADR 18 built for
  it and BE-022's scope does not name it.
- **The detection store grew eight more columns and a migration.** `0004` is the
  second `ALTER TABLE` the schema has taken, and it mirrors `0003` exactly: the
  stage arrays are one table read sideways, and a row naming no stage is a
  detection made by a rule that orders nothing.
- **A key that spans agents is still exact only at one replica**, unchanged from
  ADR 18 and ADR 19. `group_by: [origin.agent_id, ...]` keeps a story inside one
  agent and is exact at any number of replicas, which is what the shipped rule
  does and is also what makes its clock spread meaningful.
