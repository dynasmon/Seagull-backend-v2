# 18. Detection state is a bounded window of the backbone, in event time

## Context

[ADR 9](0009-an-absent-field-answers-no-question.md) made deciding a pure
function of a rule and an event, and every rule written since decides from the
event in front of it. [ADR 17](0017-noise-is-removed-from-the-alert-and-never-from-the-detection.md)
then sharpened the question rather than answering it: folding needed no state
store because the alerts table already is one, and `aggregated` — many events
becoming one detection — was named and deliberately not built, because a rule
that counts events has nowhere to put a count.

v1 answers that question by having no state at all. `workers/intelligence/rules`
runs a cycle every sixty seconds; for each rule it computes
`since, until = utcnow() - window, utcnow()` and issues a `GROUP BY` over the
whole events table. It works, and four things follow from it:

- **every window is processing time.** Replaying the same data decides
  differently depending on when the replay runs, which is the same defect ADR 17
  found in v1's suppression windows;
- **an event is counted once per overlapping cycle.** A five-minute window read
  every sixty seconds counts each event five times, and the only thing hiding
  that is the cooldown on the alert it produces;
- **downtime is silent loss.** The window is anchored to the clock, so events
  that aged past it while the worker was stopped are never evaluated by any
  cycle;
- **the group is a column.** `group_by` is checked against a hardcoded allowlist
  of event table columns, which is the dictionary [ADR 6](0006-a-rule-addresses-the-contract.md)
  removed.

## Decision

**What a rule remembers is a bounded window of observations under a key,
measured in event time — a materialisation of a bounded suffix of the backbone,
exactly as the stores are materialisations of the whole of it.**

That one sentence answers restart and replay together. State is a pure function
of the events inside its window, so **replay is not a special case: it is how the
state is built.** There is nothing to checkpoint, nothing to recover and no
changelog, because re-reading the window reconstructs it exactly. Determinism
rests on two properties, both enforced by the model rather than hoped for:

- **an observation names the event it came from**, and an event already folded
  into a key moves nothing. A batch redelivered after a crash counts once. It is
  the same argument that names a detection by the events it was decided from;
- **every window is event time.** Nothing consults the clock, so the same stream
  read a year later reaches the same state.

**The key is `tenant · rule · revision · group`, and it is hashed to a fixed
size.** The tenant is always in it and never declared, because state that could
span one is a count somebody could read past. The revision is in it because a
revised rule asks a different question and must not inherit the answer to the old
one — v1's `ssh_bruteforce_authlog_v2` could not tell a second version of a rule
from a second rule. A group value is attacker-supplied and is held for as long as
the window lasts, so the key is a digest: a 512-byte value and a four-byte one
cost the same. An absent field is its own group rather than the empty string,
which is [ADR 9](0009-an-absent-field-answers-no-question.md) carried into the
key.

**One observation carries an event id, an event time and one value.** The value
is what a cardinality counts distinct of, or which stage of a sequence the event
satisfied; it is empty when the rule only counts, and then it costs nothing. Four
of the seven kinds of state the card asks for read the summary the store answers
with — count and threshold read `Count`, cardinality reads `Distinct`, frequency
reads both `Count` and `Span`, temporal correlation reads `First` and `Last` —
and `group_by` is the key itself. A sequence reads the same window in the order
it was observed, which is why observations are held in event time rather than in
arrival order: one that arrives late lands where it happened.

**Three ceilings, all finite and all declared**, so the memory a store can occupy
is known before it runs rather than discovered under load: the longest window a
rule may ask for, the most observations one key holds, and the most keys held at
once. The product of the last two is the whole of it. Two of the three carry a
consequence worth stating:

- **a window is what a restart costs.** Rebuilding state means reading that much
  of the backbone again, which is why the ceiling on it is a day and not a year;
- **a full key discards its oldest and says so.** `Saturated` means `Count` is a
  floor, so a threshold above the per-key ceiling can never be reached, and
  BE-021 must refuse such a rule when it compiles it rather than let it silently
  never fire.

**A store at its key ceiling refuses a new key; it never evicts one to make
room.** This is a security decision and not a capacity one. Whoever can produce
events can produce group values, so an estate flooded with invented ones would
otherwise be choosing which of its real counts to forget on the attacker's
behalf — the flood would evict the state of the activity it was hiding. Refusing
keeps what exists, the refusal is answered rather than swallowed, and the caller
counts it. Keys are reclaimed instead when the stream has moved past their own
window, measured by a watermark that only ever moves forward, and only under
pressure: nothing here runs a goroutine or a timer.

**An observation older than the window it belongs to is refused, not folded.**
Folding it would report a window reaching further back than the one the rule
asked for. That is the explicit late-arrival policy BE-022 will need, decided
once, here.

**Nothing resets when a rule fires.** ADR 17 put noise removal at the alert
plane, and a cooldown inside the state store would be a second place for the same
thing, disagreeing with the first.

**No backend was chosen.** `detectionstate.Store` is one operation and names no
technology; `Keeper` is its in-process realisation, and a shared cache or a
relational table would be others. The domain is refused ClickHouse, PostgreSQL,
franz-go and the Prometheus client by `tests/architecture`, so an adapter is
where a driver can live and an executable is where one is chosen — the same seam
as the backbone source and the ruleset the engine is pinned to.

## Consequences

- **Ownership comes from the consumer group.** A partition belongs to one
  process, so a key whose group stays inside one agent is exact at any number of
  replicas. A key that spans agents — a threshold on a source address across the
  estate — is exact while the engine is a single replica, and each replica sees
  its own share when there are two. The answers are a shared store behind this
  same port, or repartitioning the stream by the group key onto a topic of its
  own. Both are named here and neither is built, because one replica is what runs
  and inventing the coordination first is how ADR 12 says a platform acquires
  four datastores nobody re-derived.
- **`Distinct` counts non-empty values.** An event that names nothing contributes
  to the count and not to the cardinality, so a rule can ask both questions of one
  key without the events that cannot answer the second distorting it.
- **The keeper reports nothing itself.** A domain package may not import the
  Prometheus client, so capacity refusals, late observations and saturated keys
  are counted by whatever calls it — which is also where they belong, since the
  same numbers mean different things to a rule that is merely busy and one that
  is being flooded.
- **The watermark is producer-influenced, and bounded.** The gateway refuses an
  event whose time is further ahead than its clock-skew allowance, five minutes
  by default, so a producer can pull reclamation forward by at most that. It
  reclaims only keys nobody is observing any more, so the cost is a count that
  starts again rather than a count that is wrong.
- **Nothing imports this yet.** BE-021 is what makes it run: it gives a rule a
  window, a group and a threshold, and it is where compiling a rule against these
  ceilings has to happen. The rule domain landed the same way and ran three cards
  later.
