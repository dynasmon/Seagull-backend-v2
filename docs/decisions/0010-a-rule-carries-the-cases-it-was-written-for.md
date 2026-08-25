# 10. A rule carries the cases it was written for

## Context

[ADR 9](0009-an-absent-field-answers-no-question.md) settled what deciding an
event means. Nothing yet says whether a rule decides what its author meant, and
that gap is what makes a detection catalogue rot: a rule is written against an
event nobody keeps, the contract or the rule moves, and the rule goes quiet
without anything failing. v1 lost detections that way and had no way to notice.

v1 got one thing right here and it is worth keeping: a rule's tests lived in the
rule file, so a rule could not be moved, copied or reviewed without them. What it
got wrong is what the tests were made of — each case carried the event as a line
of raw JSON in v1's storage shape, ten near-identical lines to a case, and a
reviewer could not tell two cases apart by reading them.

The remaining question was where a case belongs in the V2 model. A case looks
like part of a rule, and putting it there would mean it is part of the ruleset —
which is the thing a detection is traced back to.

## Decision

**A case is an event a rule was written to be sure about, and what the rule
should say about it.** It is written beside the rule in the same file, and it is
not part of the rule.

**The event is written in the vocabulary the rule matches on**, which is the
contract's own field paths:

```yaml
    tests:
      - name: a failure from an address outside the estate
        expect: match
        severity: medium
        evidence: [authentication.outcome, authentication.network.source.ip]
        event:
          authentication.outcome: failure
          authentication.network.source.ip: 203.0.113.10
```

A reviewer reads the case in the same language as the rule above it, and a
fixture naming a field that has moved is refused where it is written, the same
way the rule is.

Around that:

- **a case does not change the ruleset.** Writing one changes nothing about what
  any event decides, so the name of the ruleset does not move and a detection
  made before the case existed is still traced to the same rules. This is why a
  case is beside the rule rather than in it;
- **checking is the function the engine calls.** `Program.Check` builds the
  event and asks `Program.Decide`, so a case cannot pass against an evaluator
  the engine does not use;
- **a field a case does not name is one the event does not carry**, and a value
  the contract cannot tell from absence is refused. ADR 9 applies to a fixture
  exactly as it applies to an event, so `port: 0` is not a way to write a port;
- **there is no third answer for a false positive.** Deciding answers two ways,
  and a false-positive fixture is a case that expects no match, named after the
  false positive it documents. A third expectation would be the same assertion
  under a second name;
- **a case may hold the rule to its severity and to what the match was evidenced
  by**, so widening a rule or renaming its fields fails where it was decided
  rather than in a dashboard later;
- **the class comes from the rule.** A rule decides one class, so a case naming
  `event_class` is refused rather than quietly describing an event the rule was
  never going to read;
- **a rule with no cases is reported, not refused.** Whether an estate ships an
  untested rule is a decision, and it is made where the ruleset is chosen —
  `cmd/analysis-engine` makes it, and the answer is that it does not.

## Consequences

- `make test` is the ruleset gate. Every rule the local stack mounts is run
  against its cases with no broker, no store and no container, so a rule that
  stops finding what it was written for fails the build.
- The failure names the file, the rule and the case. It does not name a line: a
  case is found by its name, which is unique within a rule and is what the
  failure quotes.
- A control plane gets rule testing for free. `rulefile.Check` reads an `fs.FS`
  and starts nothing, so publishing a rule can run its cases before it is
  accepted — which is what BE-029 will need.
- Backtesting over a recorded dataset is not this. It reads events from
  somewhere, and that is a source, a window and a store; what is settled here is
  the shape of the assertion it will make.
- A case can only describe one event, so nothing here tests a rule that counts.
  Aggregation arrives with its own state, and its cases will carry a sequence of
  events rather than one — the same file, a wider case.
