# 6. A detection rule addresses the contract

## Context

v1's rules matched on a dictionary of canonical field names, each mapped to a
storage column: `source.ip` to `src_ip`, `user.name` to `ssh_username`. Fields
that did not fit a column were addressed through a JSON bag — `extra_source`,
`extra_action_in` — and the dictionary became a third place a field could exist,
after the event and the table. It drifted from both, and a rule naming a field
that had quietly moved matched nothing and said nothing.

v2 needs a rule language for the analysis engine. The first question is what a
rule is allowed to name.

## Decision

A rule addresses paths in `seagull.event.v1.Event`, and the vocabulary is
derived from the contract's descriptor rather than written down: what fields
exist, what each holds, and which values a choice accepts all come from the
contract. There is no dictionary to keep in step, because there is nothing to
keep in step with.

Around that, four things the model deliberately does not do:

- **the class is structural, not a predicate.** A rule declares the class it
  reads, and that decides the route it is registered on. It is not a field the
  rule matches, because the engine already routes by it;
- **a rule reads the envelope and its own class's body**, never another class's.
  A rule that reached into another body would never match, and never matching is
  worse than being refused: it fails silently;
- **negation is one node in the expression**, not an operator per comparison.
  v1 carried `neq`, `not_in` and `not_contains` because its match was a flat map
  with nowhere to put a `not`; an expression tree has somewhere;
- **there are no regular expressions, no counting, no windows and no time.** A
  pattern language hands evaluation cost to the rule author, and the ingest
  baseline already found one identifier regular expression to be most of the
  cost of admitting an event. Counting and windows are state, they arrive with
  aggregation, and a model that mixes them in from the start cannot say which of
  its rules are deterministic.

## Consequences

- A field added to the contract is available to rules as soon as the module is
  updated, and a field removed breaks the rules that named it at load, loudly,
  instead of turning them into rules that never fire.
- Rules are written against the canonical form of an event ([ADR 5](0005-the-canonical-form-is-for-analysis.md)),
  which is what the engine holds in memory and not what the store keeps. A rule
  says `ssh`, and the collector that wrote `SSH` still matches.
- Every rule is decidable from one event, so a rule test is a pure function of a
  rule and an event. That is what makes a test harness and backtesting cheap
  when they arrive.
- Sigma interoperability becomes a compilation from Sigma's selections and
  condition into this expression tree. The shapes line up; `|re` does not, and
  will have to be designed rather than imported.
- The vocabulary is as good as the contract and no better. Values that a valid
  event can never carry — an unspecified outcome, an unspecified activity — are
  still offered to rules, because what a rule may name is decided here and what
  an event may carry is decided in `internal/event`. A rule matching one is
  accepted and never fires.
