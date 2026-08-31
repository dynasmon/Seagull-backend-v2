# 17. Noise is removed from the alert plane, never from the detection stream

## Context

[ADR 16](0016-an-alert-is-a-detection-somebody-owns.md) gave detections a
producer of work: anything at or above a severity floor becomes an alert. That
is also the moment the noise problem became real. One brute-force attempt is one
detection per line of the log, so a rule that is right can still put four
thousand pieces of work in front of one person.

BE-017 asks for four things to be told apart — duplicate, suppressed, cooldown
and aggregated — with the constraint that the underlying activity must stay
visible and the evidence must survive.

v1 is instructive about all four:

- `rules/dedup.py` keyed on `(rule_id, src_ip, dst_ip, dst_port)` and then
  **normalised the key by matching a prefix of the rule id**: `ddos_` dropped the
  source, `ssh_bruteforce_` dropped the destination. Renaming a rule silently
  stopped it deduplicating, and a rule about anything other than an IP flow could
  not deduplicate at all;
- `rules/suppression.py` matched a `when` map, expired on `until`, and carried a
  `reason` that defaulted to the literal string `"suppressed"` when nobody wrote
  one;
- `alerts/fp_suppression.py` grouped alerts closed as false positives and
  suggested new suppressions, **disabled**, for a human to enable;
- every window was compared against `datetime.utcnow()`, so replaying the same
  data decided differently depending on when the replay ran.

## Decision

**Noise is removed where the work is, not where the evidence is.** All three
mechanisms sit between the detection stream and the alert store. A detection is
written to ClickHouse with its full evidence and kept for 730 days whatever
happens here. What is reduced is the operator's queue.

That is what makes the card's first criterion true rather than asserted: the
platform can avoid thousands of identical alerts *without hiding the existence of
the activity*, because the activity is a query away and the counters say how much
of it there was.

**Four words, four different things.**

| | what it means | what it costs |
|---|---|---|
| **duplicate** | another detection that is the same piece of work | folded into the open alert: a count, a `last_seen`, and a row naming it |
| **suppressed** | the estate declared it does not want this as work | no alert; counted by rule and by the reason written down |
| **cooldown** | it was closed too recently to be raised again | no alert; counted |
| **aggregated** | many *events* becoming one detection | **not built here** |

`aggregated` is deliberately absent. It is a rule that remembers events, which
needs the detection state boundary (BE-020) and thresholds (BE-021); building a
counter here would be a second place with the same state for BE-021 to reconcile.
Naming it and refusing to build it is the whole of what this card owes it.

**The estate declares the key; the code never guesses it.** `deploy/alerting.yml`
is compiled into an immutable `alert.Tuning` named by its own content, read by
`internal/alertfile` exactly as `policy.yml` is read by `internal/policyfile`. A
key is a list of parts — `rule`, `agent`, `class`, `severity`, or
`evidence:<contract field path>` — and it **must contain the rule**, so two rules
can never fold into one alert. The tenant is always in the key and is never
declared: an alert that could fold across a tenant boundary is a scope somebody
could read past.

The same vocabulary is the suppression selector, so what an estate keys alerts by
and what it silences them by are written the same way. A suppression must say
`reason` and should say `until`; an expired one is stepped over rather than
deleted, so a file still explains what an estate used to suppress.

**Every window is measured in event time.** The fold window compares the
detection's event time against the alert's `last_seen`; the cooldown compares it
against when the alert was closed. Nothing consults the clock. That is what makes
the card's deterministic tests possible, and it is the v1 lesson stated as a
rule.

**The dedup state is the alerts table.** "Is there an open alert with this key?"
and "was one closed within the cooldown?" are two queries against a table that
already exists. No Redis, no new store, and no dependency on BE-020 — because
this card is about alerts, and alerts are already relational and already
persistent.

**Folding discards nothing.** `alert_occurrences` names every detection an alert
is made of, with a unique index on the detection id, and `GET
/v1/alerts/{id}/occurrences` reads it back. That index is also what keeps a
replay honest: a detection belongs to at most one alert anywhere, so a replayed
batch answers `repeated` and moves no counter.

**A cooldown is off by default.** The built-in fold is `[rule, agent]` over
fifteen minutes with no cooldown at all. Deduplication only ever merges work
somebody has not looked at; a cooldown is the only one of the three that can keep
an operator from hearing about activity they have not decided about, so an estate
has to ask for it.

## Consequences

- **An alert is named by the detection that raised it, not by its key.** The key
  is what folds; the name is the first detection. Two alerts can therefore share
  a key over time — one closed, one open — which is exactly what a cooldown is
  about.
- **The index over open alerts is deliberately not unique.** A window bounds how
  much one alert absorbs, so activity resuming long after the last of it is a new
  piece of work rather than an unbounded count on an old one; a unique index made
  that impossible and was removed when the test for it failed. Two writers racing
  could open two alerts under one key, which is bounded, harmless, and unlikely:
  detections are keyed by agent, so one key reaches one partition and one writer.
- **`occurrences`, `first_seen`, `last_seen` and `correlation_key` cross the
  contract**, because a count nobody can see is a fold that did hide something.
  `seagull.alert.v1` gained them and `Occurrence` as `v0.7.0`.
- **The document is read at startup and not reloadable.** Changing how alerts
  fold restarts one process. The ruleset showed what the answer looks like when
  that stops being acceptable — publish to a log, activate a version — and this
  is a smaller surface than that was.
- **A suppression is counted, not recorded.** `alertstore_suppressed_total` is
  labelled by rule and by reason, which answers "how much are we hiding and why".
  There is no per-detection audit row saying "this one was suppressed"; the
  detection is in the store either way, and the document says why it would have
  been hidden.
- **Schedules were not built.** v1 could suppress by weekday and hour in a named
  timezone. `until` covers the case an estate actually writes down — "we know
  about this until the migration finishes" — and a maintenance window that
  repeats is a calendar, which is a bigger thing than this card.
- **v1's false-positive suggestion loop is now buildable and is not built.**
  ADR 16 made a false positive carry a required reason; grouping those into
  suggested suppressions is a control-plane feature with a human in the loop, and
  it belongs with the API that would let somebody accept one.
