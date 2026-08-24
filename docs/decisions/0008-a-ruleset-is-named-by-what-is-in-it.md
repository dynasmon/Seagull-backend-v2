# 8. A ruleset is named by what is in it

## Context

[ADR 7](0007-a-rule-file-is-not-the-rule.md) settled how a written rule becomes a
compiled one. A process then has to be pinned to a *set* of them, and that set
changes while events are being decided — a rule is added, a noisy one is
disabled, a threshold is corrected — without the process restarting.

That raises two questions the code cannot answer by itself later: what a ruleset
*is* called, and what happens to an event being decided while the ruleset under
it is replaced.

v1 answered neither. Rules were loaded from YAML on demand through a
module-level cache keyed by each file's modification time and size, so two
workers in the same deployment could be running different rules and nothing
noticed. There was no ruleset: the word does not appear in the v1 backend. An
alert recorded the `rule_id` that produced it and nothing else, and because v1
also carried the version inside that id (`ssh_bruteforce_authlog_v2`), an alert
could not be traced back to the rule text that made it. Neither replay nor
backtesting is possible from that position, and both are stated requirements for
validating v2 against v1 in shadow mode.

## Decision

A ruleset is an immutable snapshot, and it is **named by a digest of everything
its rules carry** — id, revision, class, severity, status, technique, the text
an analyst is shown, and the compiled form of the expression. Order does not
enter the digest, so the same rules split across different files are the same
ruleset.

Around that:

- **replacement is one atomic pointer swap.** A worker reads the current
  snapshot once and holds it for the whole of deciding an event, so a reload
  arriving in the middle changes what the *next* event is read against and never
  what this one is being read against. Reading takes no lock, because it happens
  once per event and a reload must never be able to hold the hot path still;
- **what a worker is handed is a sequence, not a slice.** A slice of the rules
  for a class is shared with every other worker, and handing one out is handing
  out the ability to write into what the rest are reading;
- **the registry never reads a file.** A `Source` gives back compiled rules;
  which source that is — a rule tree today, a control plane later — is an
  executable's choice, and the architecture suite refuses the registry `os`,
  `io/fs` and a transport;
- **a reload that fails changes nothing**, and a reload of identical rules is a
  no-op rather than a replacement, so a source that was touched rather than
  changed does not restart the clock on what the process has been running.

## Consequences

- Two processes given the same rules report the same ruleset, so whether a fleet
  agrees about what it is detecting is answerable from `seagull_ruleset_info`
  alone. That is what a counter or a load timestamp could never have said.
- A detection (BE-016) can name the ruleset that produced it, and a backtest
  (BE-018) can replay against exactly that one. Both need an identity that
  survives a restart and travels between processes; neither works with a
  generation number.
- The identity is not a version anybody can order. Which of two rulesets is
  newer is not visible from the digest, and `seagull_ruleset_reloads_total` with
  the load timestamp is what answers that instead.
- The identity changes when a description changes, and that is deliberate: a
  ruleset is the thing that produced an alert, and the alert quotes the
  description.
- Rollback is a swap rather than a load: replacing gives back the snapshot it
  replaced, so keeping one and putting it back needs no new mechanism. Staged
  rollout does not, and is not built.
- The identity is one metric series and not one per ruleset ever loaded — the
  label is reset on replacement — because a label that accumulated would reopen
  the cardinality v1 had to close after an incident.
- A ruleset that runs nothing composes and pins normally. It is a legitimate
  state on a fresh deployment and an invisible failure everywhere else, so the
  process says so at `warn` rather than refusing to start.
