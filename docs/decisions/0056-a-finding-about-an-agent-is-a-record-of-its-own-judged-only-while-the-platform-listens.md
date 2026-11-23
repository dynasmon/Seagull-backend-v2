# 56. A finding about an agent is a record of its own, judged only while the platform listens

> Amended by [ADR 57](0057-a-place-is-a-run-and-a-renewal-is-refused-before-it-is-signed.md):
> the judge tells places apart by run, finds copies and shared identities among
> them within a bound per agent, and `control-api` decides a replaced certificate
> before it signs, keeps it in the registry and publishes it to the same log,
> which it never reads back.

## Context

[ADR 30](0030-an-agent-is-alive-while-its-reports-arrive.md) made an agent's
status a record of its own and judged liveness when an agent is read. It left
findings to BE-057: "Silence, two sources for one agent — interleaving sequences,
two boots reporting one installation — configuration and policy drift, modules
disabled and restart storms", and gave every report what those need: an
installation identifier, a sequence that never repeats, the boot, how the run
before it ended.

The integration audit of 2026-11-09 (INT-10) measured what their absence costs. A
copy of an agent's state directory, started on a second machine after the
original renewed, was refused its own renewal, reported itself degraded and went
on delivering as the agent: its inventory replaced the host's, the matcher
decided 171 of the host's findings `removed`, and nothing told an operator.

Nathan decided on 2026-11-10 that silence is judged in processing time, on the
platform's clock, only while the judge has confirmed it reads the end of the
status topic, waiting a whole threshold after any stretch it could not confirm;
that a silence finding is named by tenant, agent, boot and the sequence of the
last report; that silence re-decides nothing about the past; and that a renewal
refused as already replaced, and a replaced certificate presented at a listener
(BE-101), are duplicate-identity signals that name the agent and never the
certificate. On 2026-11-21 he decided the three things the card left open: what
record a finding is, which process judges, and what keeps a gateway outage from
reading as a silent fleet.

## Decision

**A finding about an agent is a record of its own: decided from how agents
report and present themselves, by a process of its own and only while the
platform was listening, kept by a writer of its own and read by `control-api`.
It changes nothing by itself.**

### The record

`seagull.agent.v1.Finding` (contracts `v0.25.0`) is not a detection, which is a
rule matching an event ([ADR 11](0011-a-detection-is-not-an-alert.md),
[ADR 39](0039-a-detection-is-named-by-the-agent-and-identifier-of-every-event-that-decided-it.md)),
and not an alert, which is a detection somebody owns
([ADR 16](0016-an-alert-is-a-detection-somebody-owns.md)). It has a closed set of
kinds — `silence`, `copied_installation`, `shared_identity`,
`replaced_certificate` — and is named by a digest of the tenant, the agent, the
kind and the episode, so judging an episode again, after a restart or a replay,
names the finding it named before. A record is one decision about it; where a
finding stands is its newest decision, by `decided_at`. An open finding carries
no closure; a closed one says what closed it: the agent was heard, only one
source was heard, another certificate was bound, or the registry stopped
admitting the agent, which is how an operator answers any of them. A decision
names the reports it rests on by installation, boot, run and sequence, never by
what they say of the host, and a finding about a certificate says where it was
used and never which certificate it was.

### Kept and read

Decisions travel on `security.agents.findings`, keyed by the agent and kept 30
days, not compacted: a decider reads its own decisions back to learn which
findings it left open, and an open finding is decided again every day, so its
newest decision is always on the log. `agent-finding-writer` keeps them in
ClickHouse `agent_findings`, a `ReplacingMergeTree(decided_at)` ordered by tenant,
agent and finding, with no partition, for the reason `agent_status` has none,
quarantining what the contract refuses as every writer does. A closed finding
leaves the store a year after its last decision.

`control-api` reads it as it reads status and assessments: the open findings of
an agent, at most 32, when one agent is read; a listing at
`POST /v1/agents/findings/search`, under `agents:read` and within the tenants the
caller holds, paged by when a finding opened and its identifier, to the
millisecond the store keeps; and the open findings by kind, counted with the
fleet ([ADR 54](0054-a-gateway-asks-how-often-to-report-and-the-fleet-is-counted-as-it-is-read.md))
into `seagull_control_fleet_findings_open{kind}`. A reading that cannot count
them publishes neither count. A store that does not answer costs a reader the
findings and never the agent.

No alert is raised from a finding yet. Whether an operator's work queue takes
them is a later decision, and ADR 16 would be amended by it.

### The judge

`fleet-judge` is a process of its own, and the only one that decides from the
status topic. It is not `status-projector`, which folds reports and decides
nothing (ADR 30); not `control-api`, because the control plane consumes no stream
of the data plane; and not `analysis-engine`, whose state is a window in event
time ([ADR 18](0018-detection-state-is-a-bounded-window.md)), which silence
cannot be judged in. It reads `security.agents.status` whole, as a gateway reads
the agent log, with no consumer group: the topic is compacted, so that is the
newest report of every agent and the recent ones beside it, and every replica
holds the same state and names the same findings, which the store collapses. A
group sharing the partitions out was weighed and left until a fleet outgrows
what one replica holds: it would add a rebuild at every rebalance and a currency
per partition, for a state of a few hundred bytes per agent. The judge holds at
most `SEAGULL_FLEET_JUDGE_MAX_AGENTS` and judges no silence while it holds fewer
than it is sent. It follows `security.agents` for the agents the registry admits,
and judges no other, as the fleet count counts no other. It reads its own
decisions back before it judges, so a restart closes what the run before it
opened. `agent_status` keeps one report per agent and could not show two
installations interleaving; the topic does.

### Listening

A stretch counts only while the judge confirmed both halves of the platform. It
lists the ends of the status log and compares them with what it read,
as a gateway confirms its roster
([ADR 46](0046-a-revocation-is-enforced-within-the-bound-a-gateway-confirms-its-roster-by.md)).
And a gateway said it admits: every gateway publishes a
`seagull.platform.v1.GatewayBeacon` on `security.gateways`, compacted and keyed
by the gateway, every `SEAGULL_GATEWAY_BEACON_INTERVAL` (5 s), saying whether it
admits — not while its roster is stale, and not in the last beacon it sends as it
stops. A gateway counts as serving until three of its intervals pass with no
beacon, timed by when the judge heard it, and a beacon read back from before the
judge started counts for nothing. With the backbone up and every gateway
down, or every one refusing `roster_stale`, nothing an agent sends can arrive and
the status topic still reads current; the beacons are what tell that platform
from a silent fleet, for a fleet of one agent as for a large one. After any
stretch it could not confirm, the judge waits a whole threshold of an agent
before it judges that agent's silence again.

### What each kind is

- **Silence.** An admitted agent whose newest report is older than five times
  the interval it announced, the point at which its liveness reads silent, while
  the platform listened throughout. It opens at that instant, which judging again
  names the same way, and closes when the agent reports again or is no longer
  admitted. An agent whose newest report said it was stopping is silent too once
  it stays away that long, and the finding says it said so: an operator who stops
  an agent for good disables it.
- **Copied installation.** A run of an installation reports a sequence the
  installation had already passed, and it is neither the same report sent again
  nor one of the run the next run accounted for (`run.previous_seen_at`). It
  closes once only one run was heard for a silence threshold.
- **Shared identity.** Two installations write new reports as one agent in turn.
  It closes as the one above.
- **Replaced certificate.** A renewal asked with a certificate a renewal had
  replaced, decided by `control-api`, which asks the registry before it signs
  (INT-12), and, with BE-101, a replaced certificate presented at a listener past
  its tolerance. It closes when another certificate is bound or the agent is no
  longer admitted.

## What this deliberately does not do

- **Revoke, disable or refuse anything.** Offline is not revoked, and which of
  two installations is the real one is an operator's to decide.
- **Claim attestation.** A report is a claim; the platform relies on what it
  observes — that reports arrive, when, and in which order their sequence runs.
- **Re-decide the past.** Reading the status topic again decides no silence that
  was not judged while it happened.
- **Judge tampering yet.** Configuration and policy drift, modules stopped,
  privileges changed and restart storms are kinds to come, in the contracts
  release that carries them.
- **Raise an alert.**

## Consequences

- Contracts `v0.25.0`: `Finding`, `Heard`, `FindingQuery`, `FindingPage`,
  `Agent.findings`, `GatewayBeacon`.
- Two processes, `fleet-judge` and `agent-finding-writer`, and three topics,
  `security.agents.findings`, its quarantine and `security.gateways`.
- Every gateway publishes a beacon; one that cannot costs freshness of findings,
  never admission.
- ADR 30's "No findings" is answered by this record.
