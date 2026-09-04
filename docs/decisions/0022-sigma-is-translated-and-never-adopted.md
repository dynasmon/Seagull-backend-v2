# 22. Sigma is translated and never adopted, and what it can say here is what the canonical form made comparable

## Context

[ADR 7](0007-a-rule-file-is-not-the-rule.md) said that a rule file is read by an
adapter and that a second rule language would become a second adapter producing
`detection.Rule` rather than a second model. Sigma is that second language, and
BE-019 is the card.

v1 had a Sigma importer, and it is the clearest example in the tree of what
importing a foreign rule language does to a platform that is not careful:

- **it imported into the file format rather than into a model.** The importer
  built the same untyped dictionary the loader produced, so `sigma_status`,
  `sigma_import.warnings` and `blocked_selections` became fields of a rule
  alongside `severity` and `detection`;
- **a construct it could not read became an inert placeholder.** A selection
  naming an unmapped field was rewritten to `{"event.type":
  "__seagull_sigma_import_blocked__:<name>"}`, which validates, compiles, ships
  and matches nothing. An unsupported rule imported cleanly and quietly found
  nothing, which is the worst outcome a security platform has;
- **every threshold was discarded.** Whatever the Sigma rule counted, the import
  emitted `aggregation: {type: threshold, window: <timeframe>, condition: {">=",
  1}, min_events: 1}`. A rule that wanted twenty events fired on the first;
- **the missing metadata was invented.** A missing `level` became `medium`, a
  missing timeframe became five minutes, and the ATT&CK technique name came from
  a hand-maintained table of thirteen techniques that silently dropped the rest;
- **the field table mapped names that were not in the telemetry.** Its own
  documentation says it: "a field alias may be syntactically mapped but still not
  be populated in local telemetry".

Everything above is a way of making an import succeed. The card asks for the
opposite: unsupported constructs must fail explicitly.

## Decision

`internal/sigma` is an adapter. It reads a Sigma document and produces a
`detection.Rule`, which it hands to `detection.Compile` before returning it —
the same door every rule file goes through:

```text
Sigma document ──▶ translate ──▶ Rule ──▶ Validate ──▶ compile ──▶ Program
```

The domain does not know Sigma exists. `tests/architecture` already refuses a
domain package naming an adapter, so the card's third acceptance criterion is
held by the classification rather than by a rule written for this one case.

### What Sigma can say here is decided by ADR 5

Sigma compares strings **without case**. The rule language compares them **with
case**: `equals`, `contains`, `starts_with` and `ends_with` are
`==`, `strings.Contains`, `strings.HasPrefix` and `strings.HasSuffix`.
Translating one into the other quietly narrows every comparison, and a narrowed
detection rule is a missed detection.

Adding a case-insensitive operator to the rule language to serve Sigma is the
deformation the card exists to prevent. So the answer comes from the stage that
already settled the question for events:
[ADR 5](0005-the-canonical-form-is-for-analysis.md) folds the fields where case
is not meaning, and deliberately leaves the ones where it is.

Each entry in the taxonomy records what the canonical form did to its field, and
that decides what translates:

| what the canonical form does | plain comparison | `\|cased` |
| --- | --- | --- |
| folds the field | translated, literal folded to match | refused |
| keeps its case on purpose | refused | translated as written |
| rewrites the address to one form | translated, literal canonicalised | refused |
| the field holds a number or a choice | translated | refused |

`authentication.user.name` is the field this costs. It is not folded because a
Unix account name is case sensitive and folding it would merge two accounts on
every Linux host, so `TargetUserName: root` is refused and
`TargetUserName|cased: root` is translated. The refusal names the remedy.
`cased` is Sigma's own modifier, so nothing was invented to make this work.

`TestTheCaseTheTaxonomyClaimsIsTheCaseTheCanonicalFormLeaves` runs the engine's
own normalisation stage over an event carrying each mapped field and holds the
table to what comes back. A field ADR 5 stops folding is a field this build
stops translating, and the suite says so rather than an operator discovering it.

### What is translated

- **values**: a wildcard anchored at either end, which is the rule language's
  `starts_with`, `ends_with` and `contains`; `\*` and `\?` as literals; a list
  as `one_of` when every value is plain, and as `any` otherwise; `null` and
  `|exists` as `present`;
- **modifiers**: `contains`, `startswith`, `endswith`, `all`, `cased`, `exists`,
  `lt`, `lte`, `gt`, `gte`;
- **conditions**: `and`, `or`, `not`, brackets, `1 of`, `any of` and `all of`
  over `them` or a `*` pattern;
- **aggregation**: `count()` with an optional `by`, against `>` or `>=`, which
  becomes the `at_least` of [ADR 19](0019-a-rule-that-counts-decides-on-a-window.md)
  with `timeframe` as its window. `> 19` is twenty, because that is what it says;
- **metadata**: title, description, level, tags, references, false positives,
  and the Sigma id as `Source{Catalogue: "sigma", Identifier: ...}`, so a
  detection can be traced past the rule to the rule it was made from.

### What is refused, by name

A pattern in the middle of a value, `?`, `|re`, `|cidr`, `|base64*`, `|utf16*`,
`|wide`, `|windash`, `|expand`, `|fieldref`, the date modifiers, a keyword list,
a field outside the taxonomy, a log source this platform collects nothing for,
a distinct count, an aggregation that is not a count, a threshold counting down,
a `timeframe` scoping nothing and a count with no window, `2 of them`, a Sigma
correlation, a document joined to another by `action`, a filter document, a
status the upstream catalogue has withdrawn, and a missing `level`.

Each refusal carries the file, the line, the column, the rule and the part of
the document, and says what the platform cannot state rather than that the input
was wrong.

### A translated rule is a draft nothing has held to anything

It arrives as `status: draft`, so it is loaded and never evaluated, and it
arrives with no cases, so `rulefile.Check` reports it as untested and
`TestTheRulesTheStackMountsHoldTheCasesWrittenWithThem` fails if it reaches
`deploy/rules`. Two independent gates, and neither of them is a flag anybody can
forget to pass.

`tools/sigmaimport` writes what it translated as a rule file through
`rulefile.Write`, which is the inverse of the reader and is held to being so by
a round trip. The reviewer edits a document in this estate's own format and
writes the cases that say what the rule should find; publishing it is BE-029's
API, unchanged.

## Consequences

- **The importable subset is small, and it is small for a stated reason.** The
  contract carries one event class, and Sigma's own authentication taxonomy
  encodes the outcome in a Windows event identifier this platform does not
  receive. Ten of the thirteen names in the table are Sigma's; `Outcome`,
  `Activity` and `Transport` name what Seagull carries and Sigma does not. The
  table is where the subset grows, and it grows with the contract.
- **A rule from the upstream catalogue will usually be refused**, and that is the
  honest outcome rather than a failure of the translator: v1 imported the same
  rules by mapping fields its telemetry did not carry.
- **A selection the condition never names is refused.** Sigma permits it; the
  common way it happens is a filter left out of a condition somebody edited, and
  the rule then fires on exactly what its author wrote it to ignore.
- **Sigma's own status does not survive.** Standing here is about this estate,
  and a translated rule has been held to nothing of ours. A rule its catalogue
  has withdrawn is refused rather than imported as a draft.
- **A technique is not attributed.** The domain needs a tactic, an id and a name;
  Sigma carries the first two. The `attack.*` tags survive, so a later build that
  carries ATT&CK can fill the technique in from them without another import.
- **A tag Seagull's vocabulary cannot hold refuses the rule.** `cve.2021-44228`
  is not a tag here, and dropping it silently would lose metadata the card asks
  to preserve.
- **Modern Sigma correlations are the natural next step and are not this card.**
  They are a second document type naming rules by name, and they map onto ADR 19
  and [ADR 20](0020-a-sequence-is-decided-by-the-window-that-holds-it.md)
  rather than onto anything new. The legacy aggregation pipe is translated
  because its meaning is exact.
- **`rulefile.Write` writes rules and not cases.** A rule arriving from outside
  has none, and which cases it should carry is the reviewer's decision.
