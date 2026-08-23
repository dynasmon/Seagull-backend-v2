# 7. A rule file is not the rule

## Context

[ADR 6](0006-a-rule-addresses-the-contract.md) settled what a detection rule is.
Nothing turned a written one into it, and there is more than one place a written
one will come from: rule files today, Sigma later, and a control plane after
that.

v1 answered this by making the file the rule. Its loader read YAML into a
dictionary and passed that dictionary on as the rule, so the compiler, the
validator, the registry and the API all read the file format directly. What
belonged to the file — `schema_version`, `pack`, `maturity`, `environments` —
ended up as fields of the rule, and what belonged to the rule was reached
through string keys that no type ever held. A second source could not be added
without a second dictionary shape, and Sigma import became a translation into
the same untyped bag rather than into a model.

## Decision

A rule file is a representation, and it is read by an adapter.
`internal/rulefile` knows YAML and knows the layout of a rule file;
`internal/detection` knows neither. The dependency runs one way, and the
architecture suite holds it there: a rule file may not name a transport, a
database, or the operating system, because which filesystem rules are read from
is an executable's choice.

`detection.Compile` is the one door from a written rule to a runnable one:

```text
rule file ──▶ parse ──▶ Rule ──▶ Validate ──▶ compile ──▶ Program
```

Four things follow from putting compilation behind that door rather than beside
each source that feeds it:

- **a literal is compiled into the type its field holds, or the rule is
  refused.** A port compared against `-1` or against `3.5` is a rule that
  matches nothing and says nothing; the contract's own descriptor is what
  decides, so the ceiling is the one the contract states rather than one written
  down a second time;
- **a rule that can never match is refused where it is written**, and so is one
  that matches every event. The check proves emptiness rather than searching for
  it: what it cannot decide it lets through, because a compiler that guesses
  refuses rules that are fine, and that is the more expensive mistake;
- **nothing is resolved twice.** A field becomes a path of contract descriptors
  once and a long list becomes a set once, so evaluation is a walk of a tree
  rather than a lookup of a name;
- **a refusal carries a file, a line, a column, the rule and the part of it that
  is wrong**, and keeps the domain's own refusal underneath. The same error
  serves an editor and, later, a control plane.

A ruleset is read whole or not at all, and every file that is wrong is reported
rather than only the first: half a ruleset is a detection surface nobody asked
for, and an operator fixing one file at a time is an operator who cannot see
what they are fixing.

## Consequences

- Sigma (BE-019) becomes a second adapter producing `detection.Rule`, not a
  second model. Whatever Sigma can say that this language cannot is a question
  about the language, asked in one place.
- The control plane can validate a rule with nothing running: `detection.Compile`
  reads no file, opens no connection and holds no state, so a rule can be
  refused at the API before it is stored.
- A rule file carries a `schema_version` of its own, which is not a rule's
  revision and not the event schema version. The three change for different
  reasons and a file that conflates them cannot be migrated.
- The satisfiability check will refuse fewer rules than it could. It narrows one
  field at a time inside one conjunction, and it does not search combinations,
  so `not (a or b)` beside `a` is accepted today. The limit is held in a test so
  that it is visible rather than discovered.
- `go.yaml.in/yaml/v3` becomes a direct dependency. It was already in the module
  graph beneath the ClickHouse client, so nothing new is fetched or trusted.
- Rules are read from an `fs.FS` the caller provides. Nothing decides where a
  rule tree lives until an executable does, which is what keeps the same reader
  usable from a test, a container and a control plane.
