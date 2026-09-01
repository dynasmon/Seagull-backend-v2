# 19. A rule that counts decides on the window, once per event, and says what it counted

## Context

[ADR 18](0018-detection-state-is-a-bounded-window.md) built somewhere for a rule
to put a count and left it unused: `internal/detectionstate` is a bounded window
of observations under a key, in event time, and nothing imported it. BE-021 is
the card that makes it run — count, `group_by`, windows and thresholds — and its
worked example is one sentence:

```text
>= 20 failed SSH attempts, from the same source, against the same agent, inside 60 seconds
```

Three things had to be decided to write that down and mean it: where the count
belongs in a rule, what a detection made from twenty events *is*, and what
happens on the twenty-first.

v1 answers all three by accident. `rules/packs/core/baseline.yml` writes
`type: aggregate_count`, `window: 2m`, `group_by: [src_ip, dst_ip]`,
`min_events: 10` **and** `condition: {operator: ">=", value: 10}` — the same
number in two places, free to disagree — and the worker re-queries the events
table with a `GROUP BY` over `[utcnow() - window, utcnow()]` every sixty seconds.

## Decision

**A count is part of the rule, not a second kind of rule.** `detection.Count`
carries a threshold, a window and the fields that make two matching events the
same thing being counted. Matching stays what it was — a pure function of a rule
and one event — and the count is the one part of a rule answered from state
instead of from the event in front of it. There is no `type:` discriminator and
no second rule language: a rule that counts is a rule with a `count:` block, and
everything else about it is unchanged.

**One number, not two.** `at_least` is the threshold and there is nothing else;
v1's `min_events` beside `condition.value` is the shape this refuses to have.

**Every window is event time**, so nothing consults the clock, a replay a year
later decides what the original run decided, and a test controls the clock by
choosing event times rather than by waiting. That is the whole of "deterministic
with a controllable test clock": there is no clock to control.

**A detection is decided on the event that carried the count over the
threshold, and names that event.** Naming it by the whole window was the
alternative and is refused: the window may hold four thousand observations, a
detection is decided again on every event that keeps the count up, and the
product is an estate storing megabytes of repeated identifiers for one burst —
an amplification an attacker chooses the size of. What the record carries
instead is `Aggregation`: the count, the threshold, the window, the first event
time still inside it, whether the key was saturated, and the group the events
shared. The finding is the count, so the count is in the record; without it a
threshold detection and a single-event one are indistinguishable to everything
downstream.

**The threshold and the window are copied onto the detection even though the
ruleset holds them.** This is the line [ADR 11](0011-a-detection-is-not-an-alert.md)
already draws for severity and technique: what a consumer routes or renders on is
carried, and the rule's prose is not. A count of twenty-three means nothing
without the twenty it crossed.

**Nothing resets when a rule fires**, which ADR 18 decided and this card is the
first to feel. A rule at its threshold decides again on the next event that keeps
it there, so a burst of a hundred past a threshold of twenty makes eighty-one
detections — never more than one per matching event, which is exactly what the
same rule without a count would have made from the first event onwards. Folding
them into one piece of work is [ADR 17](0017-noise-is-removed-from-the-alert-and-never-from-the-detection.md)'s,
and `deploy/alerting.yml` is where the estate says so. That is what "integrate
cooldown where semantically appropriate" comes to: the cooldown already exists,
it is at the alert plane, and a second one inside the state store would be a
second place for the same thing disagreeing with the first.

**An event the window already holds decides nothing.** Folding is idempotent, so
a batch redelivered without a restart would otherwise decide on events that were
below the threshold when they first arrived and are above it now — the same
stream deciding more the second time it is delivered. The store now says an
observation was one it already held, and the engine stops there. A replay after a
restart still decides everything again, because the window is empty and rebuilt
from the stream, and every detection it writes carries the name it carried
before.

**The compiler refuses a threshold no window could hold.** ADR 18 said BE-021
would have to, and the way it is true rather than asserted is that
`detectionstate` takes its per-key and window ceilings *from the rule language*:
`MaxObservationsPerKey` is `detection.MaxCount` and `MaxWindow` is
`detection.MaxWithin`. One number each, so a rule that compiles can always be
counted by some store, and a rule that could never fire is refused where it was
written, with the line and the column.

**The bounds a deployment chose are a second refusal, at startup.** A store
narrowed below what a loaded rule asks for stops `analysis-engine` rather than
running a rule that can never fire. A rule arriving later on the published log is
answered by the store at the point of use and counted under `unbounded`, because
by then the process is running and refusing to run is no longer available.

**The group binds to what the event held, and absent is its own group.** The
binding is `detection.Binding`, which is where it belongs: `detectionstate` was
already naming `detection.Field` to describe one, and two types with the same
three fields would have been the duplication [ADR 6](0006-a-rule-addresses-the-contract.md)
removed between a rule and a column. Grouping by the class, the tenant or the
event identifier is refused: the first is shared by every event the rule reads,
the second is always in the key, and the third is shared by none, so a count
grouped by it could never reach two.

## Consequences

- **A count with no `group_by` is legitimate and is the cheapest state there
  is.** The tenant is always in the key, so an ungrouped count is one key per
  tenant. It is grouping by what a producer controls that costs keys, which is
  why the ceiling and the refusal at it are the ones ADR 18 argued about.
- **Only the first window after a restart is undercounted.** The group position
  is ahead of the window, so a restarted engine begins with an empty store and
  counts up from the events that arrive next. Rewinding the consumer by the
  window on start would fix it and would re-decide detections the store already
  holds; it is named here and not built, because what it buys is one window of
  one rule and what it costs is a startup that reads the backbone twice.
- **`Distinct` and the ordered window read are still unused.** Cardinality rules
  and sequences are BE-022's, and the state boundary already answers both.
- **A rule case says what the rule reads of one event, and not what its count
  comes to.** How many events make a detection is the engine's and is proven
  once; a case that re-stated it per rule would be testing the engine through a
  rule file. What a counting rule's cases are for is the match — which events are
  counted at all — and that is unchanged.
- **The detection store grew eight columns and a migration.** `0003` is the first
  `ALTER TABLE` the schema has taken, and the evolution the migration reader was
  written for: an estate storing detections from before thresholds existed gains
  the columns without losing the rows.
- **A key that spans agents is still exact only at one replica.** ADR 18 named
  the answers — a shared store behind the same port, or repartitioning by the
  group key — and neither is built. `group_by: [origin.agent_id, ...]` keeps a
  count inside one agent and is exact at any number of replicas; the card's own
  example does exactly that.
