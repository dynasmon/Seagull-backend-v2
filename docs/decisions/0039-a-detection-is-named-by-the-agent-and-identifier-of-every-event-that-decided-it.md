# 39. A detection is named by the agent and identifier of every event that decided it, whichever of them arrived last

## Context

[ADR 11](0011-a-detection-is-not-an-alert.md) named a detection by what decided
it, so that a replay rewrites what it wrote rather than doubling it. The
2026-09-26 security audit (SEC-01) added the tenant and an agent to the name, and
the agent it added was the one of the event in front of the engine: the event
that completed the decision. For a detection decided from one event, or from one
agent's events, that is the only agent there is. For a story whose stages came
from several agents it is whichever of them arrived last.

Such a story exists only under a rule whose group omits `origin.agent_id`, and
such a rule runs only where a reader declares that it holds the whole stream
([ADR 23](0023-state-is-owned-by-the-partition-and-rebuilt-by-reading-it-back.md)).
A sole reader interleaves its partitions in the order it fetches them, and the
read back after a restart does not reproduce that order. An external review of
`43e828a` found it on 2026-10-23 (BE-093): a failure on `web-01` and a success on
`web-02` make one story, named after `web-02` in one order and after `web-01` in
the other. [ADR 21](0021-an-incident-is-a-correlation-somebody-owns.md) names an
incident by its detection, so a sole reader's read back could open a second
incident for a story it had already opened. The detection also copied the
completing event's origin, so the agent and host a story was about, and the key
it crossed `security.detections` with, followed the same order.

Nothing on the record said which agent sent the event of each stage, and
[ADR 34](0034-a-stored-event-is-named-by-the-agent-that-sent-it.md) stores an
event under its agent, so a story across agents could not be traced back to the
events it was told from. [ADR 38](0038-an-observation-is-named-by-the-agent-that-sent-its-event.md)
had just named an observation by its agent as well as its identifier, which made
a story two agents tell under one identifier decidable — and a detection naming
that identifier twice, which `detection.ValidateContract` refused, so both of its
consumers set it aside.

A count across agents has the deeper form of the defect. It is decided on the
event that carried its window over the threshold, and which event that is depends
on the order the events were read in. No name repairs that.

## Decision

**A detection is named by the tenant, the rule, the revision it was decided at
and the events it was decided from, each by the agent that sent it and the
identifier that agent gave it; which event arrived last is no part of it.** The
events are written grouped by agent — each agent, how many of its events, and
their identifiers, sorted — so the same events in any order are the same name,
the pairing of agents to events is part of it, and no two sets of pairs write the
same bytes. One agent's events are written exactly as SEC-01 wrote them, so every
detection decided from one event or from one agent's events keeps its name: every
single-event and counting detection, every story of one agent, and everything the
shipped rules make. Only a story across agents is renamed, and it was the one
named by arrival.

**Each stage names the agent that sent its event** (`Stage.agent_id` in
`seagull.detection.v1`, contracts `v0.20.0`), which an incident's stages carry as
well. `detection-writer` stores it beside the other stage arrays (ClickHouse
migration `0010`), `alert-writer` stores it with the incident (PostgreSQL
migration `0010`), and a hunt can ask about `correlation.stages.agent_id`.

**A story across agents is about the agent of its last stage**: its origin names
the tenant and that agent, and no host. The story ended there, its event time is
already taken from there, and it is the agent an incident lists it under and the
key it crosses `security.detections` with. No host is carried because no single
host told it, and the host of whichever event completed it would tie the record
to the order again. A story of one agent, and every other detection, carries the
origin of the event that decided it, as before.

**Its consumers hold a detection to that.** A stage names an agent a certificate
could carry; every stage names its agent or none does, and none is a detection an
engine before this record made, still accepted; no two stages name the same
agent's event; and when the stages name their agents, the origin names the agent
of the last one. The check that no event is named twice compares agent and
identifier, so a story two agents told under one identifier is taken.

**Under replay, a story with one candidate per stage is one detection in every
order its partitions interleave**, and that is what the name now promises:
`TestAStoryAcrossAgentsIsOneDetectionUnderOneNameInEveryOrderItsPartitionsInterleave`
walks every order that keeps each partition's own. What no name can promise is
which events a decision cites when the order chooses them:

- a story whose stage has several candidates cites the earliest the window held
  when it completed ([ADR 20](0020-a-sequence-is-decided-by-the-window-that-holds-it.md)),
  and another order can complete it with others;
- a count across agents is decided on the event that carried it over its
  threshold and on every event that keeps it there
  ([ADR 19](0019-a-rule-that-counts-decides-on-a-window.md)), so it makes as many
  detections in every order and which events they name follows the order
  (`TestACountAcrossAgentsDecidesAsOftenInEveryInterleavingAndNamesWhatCarriedItOverItsThreshold`).

Until BE-072 repartitions the stream by the group key, so that every event of a
group is read in one partition's order, a sole reader's read back can re-decide
those detections under other names. A re-decided count is a detection of the same
rule under the same group: the alert plane folds it into the alert its key
already holds, within [ADR 17](0017-noise-is-removed-from-the-alert-and-never-from-the-detection.md)'s
window, when the alerting document keys the rule by what it groups by — as a rule
counting across agents has to be keyed, since the built-in key, the rule and the
agent, splits its detections by whichever agent's event reached the threshold. The
detection store keeps both rows, as it keeps every decision. A re-told story with
several candidates per stage is not folded, because an incident never is, so it
can open a second incident: stated here rather than fixed, and reachable only
under the sole-reader declaration.

**A deterministic merge in the sole reader was weighed and refused.** Reading the
partitions in an order a replay reproduces means holding every partition back
until all of them have passed a point in time, which a partition with no traffic
never does, so the reader would stall on its quietest agent. BE-072 gives the
order instead, by making it one partition's.

## Consequences

- A story across agents is renamed once. Only a sole-reader deployment can hold
  one — the development stack declares it and ships no rule grouping across
  agents — and the first read back after the upgrade decides it again under its
  new name, beside the one it carried, and opens its incident again.
- A detection made before stages named their agents is accepted, stored and read
  back as it was; a row from before either migration holds an empty agent array,
  and its stages come back without agents rather than not at all.
- Filtering incidents by agent finds a story across agents under the agent it
  ended on, not under every agent that took part; the stages say who did.
- `TestADetectionOfOneAgentsEventsKeepsTheNameItCarriedBeforeStagesNamedTheirAgents`
  holds the unchanged names to literals computed before this record. The tests in
  `internal/detection/contract_test.go` hold the consumers' checks, and
  `TestAStoryIsNamedByWhichAgentSentWhichEventAndNotByTheEventThatCompletedIt`
  the pairing; each fails with its part of this record removed.
- ADR 11, 20, 21 and 23 described identity without the tenant and the agent
  that SEC-01 added; their amendment notes say what it is now.
