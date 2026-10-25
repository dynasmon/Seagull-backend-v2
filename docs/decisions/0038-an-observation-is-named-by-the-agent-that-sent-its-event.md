# 38. An observation in detection state is named by the agent that sent its event as well as by its identifier

## Context

[ADR 18](0018-detection-state-is-a-bounded-window.md) made an observation name
the event it came from, so that an event folded into a key twice moves nothing: a
batch redelivered after a crash counts once, and a window read back after a
restart is the window that was lost. The name was the event's identifier.

[ADR 34](0034-a-stored-event-is-named-by-the-agent-that-sent-it.md) settled that
an identifier is the producer's to choose, and named a stored event by the agent
that sent it as well; the 2026-09-26 security audit had done the same for a
detection's identifier (SEC-01). Detection state was a third place, and an
external review of `43e828a` found it on 2026-10-23 (BE-092).

A key holds several agents' events only under a rule whose group omits
`origin.agent_id`, and such a rule runs only where a reader declares that it holds
the whole stream ([ADR 23](0023-state-is-owned-by-the-partition-and-rebuilt-by-reading-it-back.md),
`SEAGULL_DETECTION_STATE_SOLE_READER`, which the development stack sets). Under
one, whichever of two agents' events under one identifier arrived second read as
a redelivery: a count did not move, and a stage it satisfied was never folded.
Honest agents never meet — the agent names an event by a digest of its
installation and the journal cursor it read — but a compromised agent that sends
an event under an identifier another agent uses makes that agent's event fold
into nothing, and the only trace is the `repeated` outcome every redelivered
batch also takes. Two agents against a threshold of two made one detection with
distinct identifiers and none with a shared one; the same pair as the two stages
of a story told no story.

The walk that decides a sequence named events the same way. A story is decided by
the fold that made the window completable, found by walking the window again
without the event just folded, and that walk left out every observation carrying
the event's identifier. Once a key can hold two agents' events under one
identifier, an event a third agent sent under the identifier of a stage already
told would tell the story again.

## Decision

**An observation names its event by the agent that sent it and by the identifier
that agent gave it.** `detectionstate.EventName` is the pair. A key holds an event
once per name, and the walk that leaves the current event out leaves out that name
and no other. The pair is a type of its own rather than a second field beside the
identifier, so a comparison by identifier alone no longer compiles.

**The agent is the one the gateway stamped.** `origin.agent_id` is what the
gateway read from the verified client certificate and wrote over whatever the
producer put there ([ADR 2](0002-identity-comes-from-the-certificate.md),
[ADR 26](0026-an-agent-sends-into-the-tenant-it-was-registered-in.md)). Nothing
else an event says about its producer — a host name, an address — is part of the
name, so a producer chooses only the second half of its name and cannot reach one
that another agent's event holds.

**An observation without an agent is refused** (`detectionstate.ErrNoAgent`), as
one without an identifier is. The event contract requires the agent, so nothing
the engine folds lacks one; a store that took an anonymous observation would be
naming events by their identifier again.

**The instant is not part of the name**, although the sorting key of
`security_events` carries it. An agent sends a record again with the instant it
had the first time, so a redelivery is a repeat either way; and a detection names
the events of its stages by identifier, so a name carrying the instant would let
one agent's identifier fill two stages of one story, which the detection contract
refuses as an event named twice.

**What a detection reports of its events is unchanged.** A stage still names its
event by identifier alone; naming its agent is BE-093, with the contract release
it needs. Until then a story two agents tell under one identifier is decided and
names that identifier twice, which `detection.ValidateContract` refuses:
`detection-writer` quarantines it and `alert-writer` skips it, and both count and
log it. Before this record the same story was not decided at all and nothing said
so. `TestAStoryTwoAgentsToldUnderOneIdentifierIsADetectionItsConsumersTake` holds
the gap, marked `stillOpen` against BE-093.

## Consequences

- Replay, restart and a moved partition decide what they decided. A redelivered
  event carries the agent and identifier it carried the first time, so it is one
  observation however often it arrives, and
  `TestAProcessThatReadBackOverItsWindowDecidesWhatOneThatNeverStoppedDid` still
  compares the detection identifiers. State is rebuilt by reading the partition
  back, so an upgraded engine builds every window under the new names, and there
  is nothing stored to migrate.
- A rule whose group includes the agent — every shipped rule, and every rule that
  is exact at more than one replica — keeps one agent's events under a key, so
  nothing it decides changes.
- `detection_state_observations_total{outcome="repeated"}` counts an event the
  window already held under that agent's name, which is a redelivery, and never
  another agent's event.
- An observation is heavier: it holds its agent's identifier, and the index of
  what a key already holds keys on both halves. Measured with 36-byte agent and
  event identifiers, each allocated apart as decoding allocates them, a full store
  at the default bounds — 4,096 keys of 128 observations — holds 139.3 MiB where it
  held 88.3 MiB, 279 bytes an observation rather than 177. It is still a number:
  an agent identifier is at most 64 bytes, as an event identifier is. Sharing one
  agent's text across the observations of a key is the lever if the difference is
  ever measured to matter.
- `TestTwoAgentsSendingOneEventIdentifierAreCountedApart`,
  `TestTwoAgentsSendingOneEventIdentifierStillTellAStory` and
  `TestAnotherAgentsEventUnderAToldStagesIdentifierDoesNotTellTheStoryAgain` are
  the regression tests in `internal/analysis`,
  `TestTwoAgentsSendingOneIdentifierAreTwoObservations` the one in
  `internal/detectionstate`, and
  `TestASoleReaderCountsTwoAgentsSendingOneEventIdentifierApart` admits two
  agents' events through the gateway's admission onto Redpanda and has a sole
  reader count them; each fails with the identifier alone restored.
