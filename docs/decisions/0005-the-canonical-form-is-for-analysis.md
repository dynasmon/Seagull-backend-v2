# 5. The canonical form is for analysis, not for storage

## Context

Detection compares fields. A rule that fires on a service named `ssh` has to
fire when a collector wrote `SSH`, and a rule about a host has to see `web-01`
and `WEB-01.` as one host. Something has to remove those differences before a
rule is written, or every rule reimplements case folding and address parsing and
they disagree.

v1 answered this with a normalizer process and a `normalized` topic. v2 has
neither: ADR 3 made the protobuf types the event model, so there is no `extra`
map to flatten, and a raw-to-normalized topic transform would copy bytes
unchanged across an architectural boundary with no content.

That leaves two questions. Where does canonicalisation run, and what may it
change?

It could live in `internal/event`, beside the rules about what an event is.
Both the writer and the analysis engine name the domain, so both could apply it.

## Decision

Canonicalisation is a stage inside the analysis engine, reached through the
route an event's class sends it down. It is not a process, not a topic, and not
a domain concern.

It rewrites the decoded event **in memory**. The record on the backbone and the
row in the telemetry store keep what the agent sent.

It removes representation and never meaning:

- a vocabulary that is case insensitive by definition is folded — a method, a
  service name, a protocol, a Windows domain, an OS, an architecture, the
  platform's own name for a collector;
- a DNS name loses the trailing dot that only says it is absolute;
- an address gets one text form, so `::ffff:10.0.0.5` and `10.0.0.5` compare
  equal, and text that is not an address is left exactly as it arrived;
- surrounding whitespace goes.

It never touches a field where representation *is* meaning: an account name,
because a Unix account named `Bob` is not `bob`; `raw_record`, which is the line
the rest of the event was derived from; `outcome_reason`, which is written for a
human; `collection.source`, which may be a path. It never touches what the
platform itself wrote — the tenant, the agent, the gateway, the batch — because
that was assigned rather than reported.

Every string the contract carries has a decision recorded in the suite, with its
reason. A string added to the contract fails the build until someone decides.

## Consequences

- The store and the engine can disagree about the text of a field: a hunt query
  sees `WEB-01.` where a detection rule sees `web-01`. That is the point. The
  store is evidence and answers "what did the agent say"; the engine is analysis
  and answers "what is this". `event_id` is never rewritten, so a detection is
  always traceable to the row it came from.
- The writer does not normalize, and cannot: a capability may not name another
  capability, so the only way to share the stage would be to move it into the
  domain — where it would sit beside the rules about what an event *is*, which
  it is not. The boundary and the intent agree.
- Normalization has to be idempotent, because a replay normalizes an event that
  may already be canonical. It is, and the suite proves it.
- The engine reports how many events it had to rewrite, per route. Against the
  routed count that is a measure of the agents rather than of the engine.
- A new event class brings its own canonical form. The route table names the
  stage and the decision table names every string, so neither can be forgotten.
