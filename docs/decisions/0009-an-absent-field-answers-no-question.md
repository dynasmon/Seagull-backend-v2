# 9. An absent field answers no question

## Context

[ADR 8](0008-a-ruleset-is-named-by-what-is-in-it.md) settled what a process is
pinned to. What was still missing is the step that reads an event and says
whether a rule holds — and with it two questions the model had not had to answer
while nothing was evaluating anything.

The first is what a rule means when the event does not carry the field it asks
about. proto3 does not distinguish a field that was never set from one carrying
its zero value, so a port of `0`, an outcome of `unspecified` and an absent
`user` are the same observation as far as the contract is concerned. A rule
asking `port at_most 1024` of an event with no port has to mean something, and
whatever it means it will mean for every rule anybody writes.

The second is what a match owes an analyst. v1 recorded the `rule_id` that fired
and the event it fired on, and nothing about *why*: reconstructing that meant
reading the rule, reading the event and doing the comparison by hand, which is
exactly the work an alert exists to save.

## Decision

**An absent field answers no question.** Every comparison against a field the
event does not carry is false, and `present` is the one way to ask about the
field itself. Negation then says the useful thing on its own: a rule asking that
a field is not something also holds when the event never said.

**A match carries evidence**, and evidence is what the event held in the fields
the rule read — the field, what was asked of it, whether it was asked under a
negation, and the value, written the way a rule writes a literal. What was asked
*in full* is not copied: the rule is named by the match and the ruleset is named
by its own content, so the question is recoverable and the answer is what only
the event can give.

Around those:

- **evidence is the reason, not the transcript.** A disjunction is evidenced by
  the branch that held, and the branches tried before it are dropped. A
  disjunction that held nowhere keeps all of them, because under a negation all
  of them failing is why the rule matched;
- **deciding is a pure function of a rule and an event.** No I/O, nothing kept
  between calls, nothing written into the event, and no failure mode. A rule
  that needs more than the event in front of it is an aggregation, and that is
  state and a later card;
- **a rule only decides its own class**, in the executor and not only in the
  router, so a harness handing it another event gets the same answer the route
  would have;
- **the tree is walked twice on a match and once otherwise.** The common answer
  is no, and that answer allocates nothing;
- **a detection is reported by what decided it and never by what the event
  held.** A field value can carry attacker input; the fields the rule read are
  named instead, because those come from the contract.

## Consequences

- A rule comparing against a value a valid event can never carry — an
  unspecified outcome, an unspecified activity — is accepted and never fires,
  which is what [ADR 6](0006-a-rule-addresses-the-contract.md) said it would be.
- `authentication.network.source.port at_most 0` never holds, because an event
  carrying port `0` is an event carrying no port. A rule that means "the port is
  low or missing" has to say so with `not present`.
- Evidence is bounded by the rule rather than by the event: a rule listing four
  thousand addresses is evidenced by the one the event held.
- Nothing is emitted yet. A detection crosses a runtime boundary and needs a
  message in `Seagull-contracts` before it can leave the process, so a match is
  counted and reported and deliberately cannot be acted on. That release is
  planned with the detection result contract.
- Because deciding cannot fail and does no I/O, detection adds no failure mode
  to the analysis engine: it does not change what is quarantined, what is
  retried, or when the group position advances.
- Which rule fired is not a metric label. A ruleset is unbounded from the
  engine's point of view, and v1 had to close a cardinality incident; what fired
  belongs in the detection record, where it can be queried.
