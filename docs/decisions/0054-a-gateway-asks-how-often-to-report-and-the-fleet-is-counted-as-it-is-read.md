# 54. A gateway asks an agent how often to report and imposes nothing by it, and the fleet is counted the way an agent is read

## Context

[ADR 30](0030-an-agent-is-alive-while-its-reports-arrive.md) judges an agent's
liveness when it is read, from when the platform received its newest report,
against the interval that report announced. It left two things to the rest of
BE-053. The interval was the agent's alone, with "what the platform offers will
be the descriptor's, when BE-052 publishes one"; and it listed "No fleet gauges":
how many agents are silent was a question asked of the table.
[ADR 45](0045-a-listener-tells-an-agent-what-it-serves-and-decides-nothing-by-it.md)
published the descriptor and said again that offering an interval is what
remains of BE-053.

So the platform cannot ask a fleet how often to report. Each agent reports at its
own setting, `reporting.interval`, a minute unless a person changed it on the
host, between ten seconds and an hour. An installation that wants its fleet to
report less often, because it is large, or more often, because it wants silence
noticed sooner, has to touch every host, which is the maintenance invariant 18
says an operator does not do.

And nothing watches the fleet as a whole. Liveness exists only on the agents of a
page someone reads; there is no series a Prometheus rule can hold, so an estate
that went quiet in the night is found by whoever pages through it in the morning.

## Decision

**The gateway's description of the status stream names the interval the platform
asks agents to report at, a report is still judged against the interval it
announces, and `control-api` counts the agents the registry admits by liveness,
judged at one instant by the rule a listing judges each agent by.**

### The interval is asked for in the stream's description

Contracts `v0.24.0` give `seagull.platform.v1.Stream` an `interval`, set on a
stream whose every record announces when the next one comes — the status stream
today — and absent from the others. The gateway fills it from
`SEAGULL_GATEWAY_STATUS_INTERVAL`, a minute by default, the agent's own default,
and refuses to start on one outside the ten seconds to an hour a report may
announce: a gateway never asks for an interval it would refuse.

The bounds themselves are not described. They are the status contract's, fixed
by its schema version, and ADR 45 keeps a field's limits out of the descriptor.

What an agent does with what it is asked is the agent's (AG-014). Today's agent
reads no descriptor and reports at its own setting.

### It is asked for and never imposed

A report is judged against the interval it announces, as ADR 30 has it. An agent
that keeps another one within the bounds — its host's setting, or a policy's if
one comes to set it — is admitted and is not taken for one that went quiet;
judging it against the interval the platform asked for would make an agent told
to report rarely look silent, which is the reason ADR 30 gave. Two gateways told
different intervals ask for different ones, and nothing about liveness changes,
since every report carries its own.

### The fleet is counted where an agent is read

Every `SEAGULL_CONTROL_API_FLEET_INTERVAL`, thirty seconds by default,
`control-api` reads the agents the registry admits — pending and active — with
the tenant each was registered in, and what was last heard of each: when its
newest report arrived, the interval it announced and whether it said it was
stopping. Those three are the columns `agent_status` keeps beside the report for
a fleet (`interval_ms`, `condition`), so no report is decoded; they are read a
thousand agents at a time within their tenants, by the sorting key, as a listing
and the rollout evaluator ([ADR 32](0032-a-rollout-opens-a-release-wave-by-wave-and-pauses-on-what-agents-report.md))
read reports. Every agent is judged at one instant by
`agentstatus.Heard.Liveness`, the rule `agentstatus.Report.Liveness` now judges a
listed agent by, and the count is published:

```text
seagull_control_fleet_agents{liveness="active|late|silent|stopped|unspecified"}
seagull_control_fleet_readings_total{outcome="read|unreadable"}
```

One series per liveness, zeros included. `unspecified` is an agent that never
reported, or whose newest report the store no longer holds after its year.

- **Admitted agents only.** A disabled, revoked or decommissioned agent is
  refused, so its silence is what somebody decided; counted, it would make the
  number of silent agents grow for as long as the registry remembers it.
- **Not by agent and not by tenant.** The count is the platform's. A tenant's
  agents are read through the listing, within the tenants its caller holds.
- **A reading is whole or not at all.** One that fails, or outlasts its interval,
  keeps the count read before it and is counted `unreadable`; no partial fleet
  is ever published.
- **Every replica counts.** Each replica of `control-api` reads the whole fleet
  and reports the same numbers; a rule reads them with `max`.

Measured on the development host (one PostgreSQL and one ClickHouse, the test
Compose stores): 100,000 registered agents in 20 tenants, a tenth of them
disabled and a seventh never reported, are read and counted in 1.0 to 1.6
seconds, and the counts equal those worked out independently of the code.

### Why it is counted here

Liveness is judged when it is read (ADR 30), so a count judged the same way, at
one instant, is what an operator paging through every agent would have read
then: the count and the listing never disagree. The table was designed for it —
its columns are "what a fleet is asked about without decoding every report" —
and the rollout evaluator already reads it on a timer.

It is not BE-057's judge. That judge decides findings, in processing time, from
the status topic, and only while it can confirm it reads the topic's end, as
[ADR 46](0046-a-revocation-is-enforced-within-the-bound-a-gateway-confirms-its-roster-by.md)
confirms a gateway's roster. A count decides nothing, so it needs neither the
topic nor the guard, and which process hosts the judge stays BE-057's to decide.

What it costs: while `status-projector` falls behind, the reports it has not
folded are not in the table, and agents grow late and silent in the count as they
do in every listing. The projector's consumer lag is what tells the two apart, so
a rule on silent agents is read beside it.

## What this deliberately does not do

- **Impose the interval.** No report is refused for announcing another one
  within the bounds.
- **Describe it on `control-api`'s agent listener**, which serves no stream.
- **Count conditions.** How many reports say an agent is degraded is counted as
  they arrive, by the gateway and the projector; which agents are degraded now is
  read from the listing.
- **Decide anything.** No agent is disabled, revoked or refused for a count, and
  no finding is made from one (BE-057).

## Consequences

- Contracts `v0.24.0`. The gateway's descriptor is an answer an agent reads, so
  it is recorded again ([ADR 48](0048-every-answer-an-agent-reads-is-recorded-here-and-changes-only-by-a-version-decision.md))
  with the status stream's `interval`; the protocol does not change, and an agent
  that does not know the field reads the rest as before.
- `control-api` reads the whole registry and `agent_status` every thirty seconds
  in every replica: one query of the registry and one read of the status store
  per thousand admitted agents.
- `agentstatus.Report.Liveness` judges through `agentstatus.Heard`, so a listing
  and the count cannot drift apart.
- An installation changes how often its fleet reports with one setting, once its
  agents read the descriptor (AG-014).
- ADR 30 and ADR 45 are amended by this record.
