# 46. A revocation is enforced within the bound a gateway confirms its roster by, and a decision the log was never told is an alarm

## Context

[ADR 24](0024-an-agent-is-registered-by-the-control-plane-and-refused-by-the-gateway.md)
carries what the registry decides about an agent to every gateway on
`security.agents`: the control plane writes the registry, then publishes the
decision, and a gateway replays the log before it serves and follows it after.
A decision the backbone refused is outstanding in the registry and published
again by the announcer's sweep.

Nothing measured how long that takes or said what happens when it does not
happen. A gateway's follower blocks in a fetch the client retries on its own,
so a gateway that stopped hearing the log kept admitting by what it last heard,
silently; the announcer counted outstanding decisions and not how old they
were; and the agent's Core gate needs a revocation deadline it can cite
(BE-055). The agent measured 6.8 ms on one host in September, outside any load.

## Decision

**A gateway admits only by a roster it confirmed recently.** Every
`SEAGULL_GATEWAY_ROSTER_CHECK_INTERVAL` (5 s) it lists the ends of the agent log
and compares them with what its follower delivered; when nothing the log held
was left undelivered, the roster was current at the moment it asked. Once the
last such moment is older than `SEAGULL_GATEWAY_ROSTER_STALE_AFTER` (30 s), or
before the first one, every stream and the descriptor answer
`503 roster_stale` with `Retry-After`: an agent keeps its batch and sends it
again, which it already does for any `503`, and an agent the registry revoked
is never let in for want of news. The roster is current again at the next
confirmation.

**So the deadline is the bound.** Every serving gateway refuses an agent within
30 seconds of its revocation reaching `security.agents`, or refuses every batch.
In practice it is milliseconds: with three gateways following the log while the
backbone carried 20,000 telemetry records a second and 1,500 other decisions a
second, 100 revocations reached all three in 0.7 ms at the median, 2.1 ms at the
99th percentile and 3.3 ms at worst, over three runs. A gateway that stopped
reading the log went stale one bound after it stopped. With the backbone stopped
for 45 seconds, a gateway's roster went stale 29.5 seconds in, the first
revocation once it started again was acknowledged 5.5 seconds after the start
and enforced microseconds later, and the roster was current 5.5 seconds after
the start; the follower came through the outage without ending.

**The control plane's half is measured and alarmed, not bounded by refusing.** A
decision reaches the log as the registry records it; one the backbone refused
is published by the announcer's next sweep, now every
`SEAGULL_CONTROL_API_ANNOUNCE_INTERVAL` of 5 s, where it was 30.
`seagull_control_agent_admissions_oldest_outstanding_seconds` says how long the
oldest decision has waited, and `SeagullAgentDecisionUnpublished` fires once it
passes a minute. A gateway cannot tell a decision the log never received from
one never made, and refusing for it would tie every batch to the control
plane's uptime.

**What a gateway exports.** `seagull_ingest_roster_confirmed_age_seconds` against
`seagull_ingest_roster_stale_after_seconds`, which `SeagullAgentRosterStale`
compares; `seagull_ingest_roster_behind_records`;
`seagull_ingest_roster_applied_age_seconds`, how old the newest decision it
applied is; `seagull_ingest_roster_checks_total` by `current`, `behind` and
`unreachable`; and the streams count `roster_stale` refusals like any other. The
log says `agent_roster_stale` and `agent_roster_current` when it changes.

## What this deliberately does not do

**A certificate a renewal replaced still authenticates at the gateway until it
expires.** BE-055 asked for this to be revisited once propagation was measured,
and it is kept, as [ADR 25](0025-the-platform-signs-the-identity-it-binds.md)
left it: a replaced certificate can no longer renew, and it stops working when
it expires, within the certificate lifetime the control plane issues. Refusing
it at the gateway needs the admission record to carry the fingerprint bound to
the agent, which is a contract release, and a rule for the connections an agent
opened with the certificate before it renewed, which changes the agent; neither
is worth the change while revoking the agent remains the answer to a key
believed copied.

**A partition between the control plane and the backbone is not refused.** The
gateways admit by the last decision the log holds, and the alarm says a newer
one is waiting.

## Consequences

- [ADR 24](0024-an-agent-is-registered-by-the-control-plane-and-refused-by-the-gateway.md)
  is amended: a gateway refuses every batch while it cannot confirm its roster.
- A backbone outage longer than the bound turns `503 backbone_unavailable` into
  `503 roster_stale` for a gateway that could not publish anyway; both keep the
  batch.
- `make test-load` stops and starts its broker for the outage evidence; the
  propagation and the stale roster are in `make test-integration`.
- `deploy/prometheus/agent-roster.yml` holds the two alerts, tested by
  `make test-alerts` and held to what the processes export by a test.
- The agent's Core gate (AG-039) can cite the deadline: 30 seconds from the log,
  measured in milliseconds.
