# 15. A ruleset is published to a log, and the pointer is the only mutable thing

## Context

[ADR 8](0008-a-ruleset-is-named-by-what-is-in-it.md) made a ruleset's identity
its content, and [ADR 7](0007-a-rule-file-is-not-the-rule.md) made the file it
is written in an adapter rather than the model. Until BE-029 the only adapter
was a directory the analysis engine reads at startup, which meant changing what
detects something required reaching the engine's disk and restarting it.

BE-029 asks for validation, versioning and controlled rollout, and its hard
requirement is that `control-api` must not reach into the engine's memory. That
leaves the question the backlog notes had been carrying: somewhere for a ruleset
to live that is neither the engine's disk nor a hot call from one plane to the
other.

Three answers were possible. A relational store in the control plane, with the
engine fetching over mTLS, is the obvious CRUD shape — and it introduces
PostgreSQL in the same card as the API, and makes the data plane unable to start
detecting when the control plane is down. Keeping a store *and* publishing for
propagation is the same cost with two sources of truth to reconcile. The third
is that the platform already owns a durable, ordered, replayable log, and both
processes already speak it.

## Decision

**A published ruleset is a record on `security.rulesets`, and the topic is
compacted.** Every version is keyed by its own content id, so compaction keeps
all of them for as long as the platform lives. One reserved key, `active`,
carries which version to run; compaction keeps only the last record written
there, which is what makes that key a pointer and every other key immutable.
The topic has one partition, and that is not a setting: a version and the record
activating it are only meaningful in the order they were written.

**Nothing invalid reaches the log.** `control-api` parses the documents with the
same `rulefile` reader the engine's disk tree uses, compiles every rule with
`detection.Compile`, and runs the cases written beside them. A ruleset that does
not compile is answered with the file, line, column, rule and part that is
wrong; a ruleset whose own cases say it is wrong is refused too. Only then is a
version written.

**Nothing invalid is run, either.** A reader recompiles every rule out of the
record and holds the ruleset to naming itself: a record whose rules do not hash
to the id it carries is refused rather than pinned. Publishing and running are
checked independently, so neither trusts the other.

**Publishing and activating are two acts.** Publishing stores a version and
starts nothing. Activating points at one. Rolling back is therefore not a
reconstruction — it is a pointer at a version that is still on the log and
cannot have changed, and nothing is ever deleted to undo a rollout.

**What crosses the boundary is the rule, not the document.** `seagull.ruleset.v1`
carries the rule as a typed expression tree, so a process that runs rules never
learns a file format — v1's mistake, where the loader's dictionary became the
rule and every consumer read YAML. The cases travel with it and do not change
the ruleset's identity, so writing a case is not a rollout.

**The engine's rule tree becomes its bootstrap.** It runs the tree it ships with
until the log names something to run, and the log wins from then on. An engine
that cannot reach a control plane still detects.

## Consequences

- What runs can be changed, and changed back, without reaching any process's
  disk or memory, and the change survives every process restarting.
- The log is the audit trail. Every version records who published it and when,
  every activation records who activated it and what it replaced, and neither
  can be edited afterwards.
- `control-api` gains a backbone client and no longer starts without one. It is
  the first control-plane process to depend on the data plane's substrate, and
  the reason is that the substrate is the only durable thing both planes share.
- Still no PostgreSQL. Sessions remain per-process state a restart may lose, and
  the first thing that will genuinely need a relational store is a session store
  shared across replicas, not this.
- A ruleset is published whole, so one must fit in one record. The listener
  states its own ceiling on the documents it reads rather than discovering the
  broker's; a ruleset large enough to hit it wants rules and manifests as
  separate records, which is a change this topic's keying already allows.
- A control plane applies what it publishes to its own catalogue immediately, so
  a caller can read back what they just published. With a second replica the log
  order decides and the replica converges when it reads the record.
- Draft rules have no home on the server. The document somebody is editing stays
  with them until it is good enough to publish, which is what keeps the control
  plane free of mutable per-author state.
- `hunt.Scope` still derives its tenants from the certificate. BE-029 did not
  need to join the two paths, so [ADR 14](0014-a-token-says-who-and-the-policy-says-what.md)'s
  note now falls to BE-030.
