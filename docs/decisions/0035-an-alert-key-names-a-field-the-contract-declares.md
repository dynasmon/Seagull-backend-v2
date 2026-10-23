# 35. An alert key names a field the event contract declares, and reads what the detection holds in it

## Context

[ADR 17](0017-noise-is-removed-from-the-alert-and-never-from-the-detection.md)
let an estate key alerts and select suppressions by `evidence:<contract field
path>`. Nothing held a document to the contract that sentence names. A part was
accepted whatever followed the prefix, and a field no detection carried read as
absent — the same absent for every detection of the rule, so the part separated
nothing.

That is how the development stack shipped. `deploy/alerting.yml` keyed
`ssh.failed_password_from_outside` on `evidence:authentication.source.ip`, and
the contract calls the field `authentication.network.source.ip`. Every external
attacker of an agent folded into one alert for an hour, and once an analyst
closed it the thirty-minute cooldown kept any new attacker of that agent from
becoming work. The detections were stored; nobody was told. The 2026-10-02
completeness audit found it (AUD-01), and the test fixture beside the reader used
the same path, so the suite held the mistake in place.

Driving the shipped rules through the engine for BE-044 found two more ways to
the same silence:

- `ssh.repeated_failed_password` was keyed on the right path, but a rule that
  counts *groups* by the source address and compares only the outcome and the
  protocol. The address is in the detection's `aggregation.group`, not in its
  `evidence`, so the part was absent there too: one alert per agent per hour,
  and a one-hour cooldown once it was closed.
- Evidence holds text the way a rule writes a literal — `"203.0.113.10"`, quoted
  ([ADR 11](0011-a-detection-is-not-an-alert.md)) — and a selector compared what
  an operator writes, `203.0.113.10`, against it. A suppression by an address, a
  user or a host never matched anything.

## Decision

**A part is refused when the document is read unless the field it names is in
the event contract's vocabulary** — the one [ADR 6](0006-a-rule-addresses-the-contract.md)
derives from the descriptor and compiles rules against. The check is the same for
a key and for a suppression selector, in `alert.ParsePart` for a document and in
`alert.NewTuning` for anything else that builds a tuning. A refusal names the
file, the line, the column and the part, and `alert-writer` does not start: a
document that cannot keep two attackers apart is not run.

**`evidence:<field>` reads what the detection holds of the field**, which is not
only what the rule compared:

1. the evidence, when the rule compared the field;
2. otherwise what a counting rule grouped its window by (`aggregation.group`);
3. otherwise what an ordered rule grouped its story by (`correlation.group`).

Each is a statement of what the events held in that field, and the value is read
as the event carried it: text unquoted, a choice by its short name, a number as a
number. A key and a selector read it the same way, through `detection.HeldIn`, so
the convention evidence is written in has one owner — the package that writes it.
An alert key names an event field and stays right when a rule's author turns a
rule that compares an address into one that counts by it.

**A key part a detection says nothing about is told once per rule and part, and
counted every time.** It is not refused: the detection is legitimate and the key
still folds by everything else it names. The first time a rule's detection is
keyed on a field the detection holds nothing of, `alert-writer` logs
`alert_key_part_unspoken` with the rule, the part and the tuning, and every such
detection is counted in `alertstore_unspoken_key_parts_total`, by part.

That is as early as the platform can know. BE-044 asked for the warning at
startup without coupling `alert-writer` to the ruleset, and the two cannot both
hold: which rules are active is the ruleset's to say
([ADR 15](0015-a-ruleset-is-published-to-a-log.md)), and a writer that read the
ruleset log to lint its document would be a second consumer of rulesets whose
answer goes stale at the next activation. The first detection of a rule is the
first moment its key can be wrong, and what it says stays current across every
ruleset the engine activates.

## What this deliberately does not do

- **Refuse a fold for a rule that does not exist.** A rule id in the document is
  compared for equality; a fold for a retired rule is inert, and an estate writes
  one before the rule is published.
- **Check addressability by class.** A fold names no class, so a field of one
  class's body is accepted for any rule; a rule of another class never speaks of
  it, and the warning says so.
- **Tell about a selector a detection says nothing about.** A suppression that
  never matches costs more work rather than less, and the counter of what it hid
  stays at zero.
- **Label the counter by rule.** Rule identifiers arrive in records; the part is
  bounded by the document, and the log line names the rule. The pairs already
  told are bounded at 1,024.

## Consequences

- The shipped document keys both rules on
  `evidence:authentication.network.source.ip`. `tests/e2e` drives the shipped
  rules through the engine and their detections through the writer with the
  shipped document: two attackers of one agent are two alerts per rule, and no
  key part goes unspoken. A document regressing either way fails it.
- Correlation keys move once. A part that read absent now reads the address, and
  text is hashed unquoted, so an alert left open under an old key absorbs nothing
  more and the next detection raises a new one. No production data exists yet
  (stage S0).
- A document that was wrong and ran now refuses to start, and says where.
- `internal/alert` names `internal/detection`, domain to domain, for the
  vocabulary and for what a detection holds.
