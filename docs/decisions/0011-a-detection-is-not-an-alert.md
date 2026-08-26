# 11. A detection is not an alert

## Context

[ADR 9](0009-an-absent-field-answers-no-question.md) settled how a rule decides
an event, and [ADR 10](0010-a-rule-carries-the-cases-it-was-written-for.md)
settled how a rule is held to what it was written for. Neither of them let the
engine say anything: a rule matched, the match was counted and written to a log
line, and the process that decided it was the only thing that ever knew.

The blocker was never the evaluation. It was the *output*. A detection is a new
kind of record crossing a runtime boundary, and three questions had to be
answered before one could leave:

**What is the record?** v1 answered this by having one table. `AlertModel` holds
the rule that fired, the rule's version and hash, the ruleset version, the
severity, the ATT&CK attribution and a JSON bag of details — and, in the same
row, `status`, `disposition`, `assigned_to`, `acknowledged_at`, `closed_by`,
`triage_notes` and `false_positive_reason`. What the platform found and what a
person did about it are the same object, which means the analytical stage cannot
write without touching a row an operator owns.

**What names it?** A batch that is published before its offset is committed is a
batch that will be published twice, because that is what a retry is. Either the
record identifies itself the same way both times or every replay doubles the
findings.

**Where does it go?** The engine already consumes `security.events.raw` in its
own group. Writing to a store from there would put the shape of an alert table
inside the thing that decides what an alert is about.

## Decision

**A detection is not an alert, and it is not an event.** `seagull.detection.v1`
holds a `Detection`: what was found, by which rule, at which revision, out of
which ruleset, about which agent and tenant, from which events, with the
evidence that decided it. It carries no status, no assignee and no disposition.
Those belong to an alert, which has a lifecycle and an owner, and which is a
later card.

**A detection is named by what decided it**: the rule, the revision it was
decided at, and the events it was decided from — sorted and length prefixed, as
a ruleset names itself. Nothing about when, and nothing about the process. The
same events decided against the same rule name the same detection, so a replay
rewrites what it already wrote.

The ruleset is deliberately *not* part of that name. It names the whole set, so
an unrelated rule arriving would rename every detection the others made and a
replay after any edit at all would duplicate what it found. The revision is what
says a rule changed. A detection carries the ruleset beside its identity, so two
detections sharing a name and disagreeing about the set they came from is a
visible state rather than a silent one.

**It leaves on the backbone**, to `security.detections`, keyed by the agent it is
about. The engine publishes; whatever stores a detection is a consumer of its
own. Neither knows the other's schema.

**It is durable before the group position advances.** The batch is decided, the
detections it produced are published, and only then is the offset committed —
the same order the writer keeps against ClickHouse, and the same retry: tried
again with a widening delay until the backbone takes them or the process stops.
Nothing is dropped to make progress, so a backbone that will not take a detection
becomes visible consumer lag rather than a finding nobody was told about.

Around those:

- **the detection names the rule and does not repeat it.** Id, revision, name and
  where the rule came from; not its description, its false-positive guidance, its
  response, its tags or its references. The ruleset is named by its own content,
  so the rule text is recoverable from the set rather than copied into every
  detection the set makes;
- **evidence is where a value the event carried is allowed to live.** ADR 9 keeps
  it out of log lines because a field value can carry attacker input. The
  detection record is the place it belongs, and it is the reason the record
  exists;
- **evidence is a set of what the event said, not a list of what the rule
  asked.** Carrying it across the boundary is what made this visible: the rule
  the local stack ships refuses three private prefixes on one field, and because
  ADR 9 deliberately does not keep the literal that was asked about, the three
  branches produced three identical observations. One answer is written down
  once however often it was asked; two answers that differ stay two, so what is
  dropped is a repetition and never a distinction;
- **severity crosses as a closed set and stays a word in the domain.** One map
  holds both, so a severity the platform cannot report is a severity a rule
  cannot be written with;
- **the whole batch shares one decision time.** It is when the engine reached
  those records, and it is deliberately no part of how a detection is named.

## Consequences

- The engine has a stage that can fail for more than one reason, which is what
  BE-008's commit semantics and BE-009's retry classification were waiting for.
  A publish that cannot succeed now holds the consumer where it is.
- `security.detections` is a third topic in the declared topology, applied by
  `backbone-migrator` like the other two. The event writer verifies only the
  topics it depends on, because the topology now carries one it never touches.
- A detection is bigger than the match it came from: the evidence is copied and
  so is the origin. Detections are rare next to the telemetry they are made
  from, and the topic carrying them is narrower than the one it reads.
- Two detections can share a name only if a rule's logic changed without its
  revision moving. The ruleset each carries is what makes that visible.
- Nothing materialises a detection yet. The record is on the backbone and
  BE-026 is what reads it; until then a detection is durable and unqueryable,
  which is the same shape the slice had before the store arrived.
