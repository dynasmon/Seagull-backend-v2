# 23. Detection state is owned by the partition that feeds it, and rebuilt by reading that partition back

## Context

[ADR 18](0018-detection-state-is-a-bounded-window.md) said what a rule
remembers: a bounded window of observations under a key, in event time, held by
the process that decided the events. It then made two claims about that, and
built neither.

The first is about restart:

> replay is not a special case: it is how the state is built. There is nothing
> to checkpoint, nothing to recover and no changelog, because re-reading the
> window reconstructs it exactly.

Every word of that is true and none of it happens. `broker.Consumer` commits the
group position after each batch is durable, and `cmd/analysis-engine` builds an
empty `detectionstate.Keeper` at startup. A process that resumes at its
committed position resumes with a window it never observed. The worked example
of BE-021 is the failure:

```text
window = 10 minutes, threshold = 20

15 matching events decided, positions committed
the process is killed
5 more events arrive

the window holds 5 and the rule says nothing,
and twenty events inside ten minutes went unreported
```

Nothing reports it. There is no error, no metric and no log line: a security
platform that fails this way tells nobody it failed.

The second claim is about scale:

> A key that spans agents — a threshold on a source address across the estate —
> is exact while the engine is a single replica, and each replica sees its own
> share when there are two.

Also true, also silent. `security.events.raw` is keyed by `origin.agent_id`, so
one address seen by three agents lands on three partitions. A rule grouping by
that address alone compiles, activates, runs, and reports a third of what it was
written to find, on every replica, for ever.

Both are the same defect wearing two hats: **state ownership is not stated
anywhere, so nothing can check it.**

## Decision

**A rule is executable here only if the stream keeps its group together.**
`detectionstate.Partitioning` says what the backbone guarantees — the fields a
record is keyed by — and answers one question about a rule: does every event
that shares its group also share a partition? A group that contains the fields
the stream is keyed by does; one that does not is counted in as many places as
the stream is divided into, and none of those counts is the answer. The tenant
is part of every key without ever being grouped by, so a stream keyed by the
tenant keeps every group together and a stream keyed by nothing keeps none.

This is deliberately not "every `group_by` must contain `origin.agent_id`". It
is a comparison between two declarations, so repartitioning the stream by
another field, or adding a stream keyed differently, changes one constant rather
than a rule in the compiler.

**A deployment may declare that it reads the whole stream, and the declaration
is verified.** `Sole` admits any group, because a reader holding every partition
holds every count. It is checked against what the group actually assigned the
process, and a reader that claims it and does not have it **stops**. It stops
only if the ruleset it is running contains a rule that needed the claim, so a
second replica is free wherever no rule depends on being alone. An explicit
outage is the correct answer here, and a quietly partial detection surface is
not.

**Active means executable.** The bounds check that lived in `keeping()` for the
ruleset a process starts with now runs wherever a ruleset becomes active,
including on a ruleset published to `security.rulesets` while the engine is
running, and it now checks partitioning as well as window and threshold. A
ruleset carrying one rule this deployment cannot answer is refused **whole**,
counted as `ruleset_activations_total{outcome="refused"}`, and the last ruleset
the process could answer keeps running. Rules that do not run are not held to
it: a draft is written and not evaluated, and a translated Sigma catalogue
arrives as drafts ([ADR 22](0022-sigma-is-translated-and-never-adopted.md)).

**State is rebuilt by reading its partition back, and by nothing else.** When
the group hands a process a partition — at startup, and again at every
rebalance — the reader is put back to the first record inside the window the
running rules need, and reads forward from there. That is ADR 18's claim, made
to happen:

```text
recovery = the longest window anything running keeps, bounded by the store,
           plus the clock skew the gateway admits
```

The skew term is what makes it exact rather than approximately right. A window
is measured in event time and the stream is ordered by arrival, and the gateway
refuses an event more than `SEAGULL_EVENT_MAX_CLOCK_SKEW` ahead of its clock, so
an event inside the window can sit at most that far behind its own place in the
stream. Nothing else can.

**The replay decides what it already decided, on purpose.** Everything between
the rewind point and the committed position was published before that position
advanced, and is published again. It is safe for the reason retrying a publish
is safe: a detection is named by the rule, its revision and the events it was
decided from, so whatever materialises it rewrites rather than doubles. The
replayed path is the crash path the pipeline already had and already tested,
taken deliberately and bounded by a window. A second mode that folded state
without publishing would be a new set of semantics to get wrong, in exchange for
duplicate rows a `ReplacingMergeTree` was chosen to absorb.

**The reader is never moved forward.** A process further behind than the window
it has to rebuild keeps its committed position, because meeting the window would
step over telemetry nobody has decided yet. Recovery only ever reads more.

**Nothing is discarded when a partition is revoked.** A key is fed by exactly
one partition, because that is what admitting the rule established; state for a
partition this process no longer holds simply stops moving, and is reclaimed by
the watermark under pressure like any other key past its window. If the
partition comes back, the rewind folds in what the other replica decided
meanwhile, and an observation names the event it came from, so nothing is
counted twice. Revocation needs no cleanup because the model already answers it.

## Consequences

- **A restart costs a window of re-reading**, which is what ADR 18 said the
  ceiling on a window was for. `SEAGULL_DETECTION_STATE_WINDOW` is now the
  number that bounds both the memory a store occupies and the work a rebalance
  does, and a deployment running no stateful rule reads nothing back.
- **The backbone learns nothing about rules.** `broker.Recovery` is a function
  of one integer returning a duration or a refusal; `tests/architecture` refuses
  `internal/broker` naming `internal/analysis` or `internal/ruleset`, so the
  adapter is told the answer rather than working it out. What the topic has is
  read from the declared topology rather than from the brokers, because
  `VerifyTopics` already refuses to serve when the two disagree and the migrator
  refuses to repartition: asking again at every rebalance would add a way for a
  transient admin call to stop a process that had nothing to rebuild.
- **A refused assignment stops the process rather than rejoining.** Rejoining
  would meet the same topology and the same rules, and detection would be
  quietly partial for as long as it kept trying.
- **A backbone that cannot say where the window starts stops the reader too.**
  Failing open would start it with an empty window and no way to know, which is
  the failure this record exists to remove.
- **The declaration and the key cannot drift.** `broker.PartitionedBy` is stated
  beside the producers that write the key, and a test reads it back off an
  encoded record through the same field vocabulary a rule uses.
- **Shutdown commits what it finished.** The batch is durable before the
  position advances, so cancelling the commit with the process would replay
  decided work on every deployment; a stopping reader commits on a budget of its
  own and then stops.
- **This is not exactly-once and does not claim to be.** Events are delivered at
  least once, detections are named so that publishing one twice says the same
  thing twice, and state is a pure function of the events inside its window. The
  guarantee is that **a process that recovered decides what a process that never
  stopped would have decided**, and it is a test rather than a sentence:
  `TestAProcessThatReadBackOverItsWindowDecidesWhatOneThatNeverStoppedDid`
  compares the detection identifiers.
- **What was not built.** A changelog topic, a snapshot store and a shared state
  cache are all still unbuilt and all still available. Each of them is a second
  source of truth about a window that a bounded suffix of the backbone already
  holds, and none of them is needed until a rule wants a window longer than it
  is reasonable to re-read.
