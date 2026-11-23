# 58. A listener admits an agent only on the certificate in force, and tolerates the one a renewal replaced for a declared while once it learns of the renewal

## Context

[ADR 25](0025-the-platform-signs-the-identity-it-binds.md) left a certificate a
renewal replaced working until it expired, and called it "not an oversight": a
fingerprint on the admission record "would make a renewal fail closed while the
compacted topic caught up, breaking ingest at the moment an agent did the right
thing".
[ADR 46](0046-a-revocation-is-enforced-within-the-bound-a-gateway-confirms-its-roster-by.md)
revisited it once propagation was measured and kept it deferred: refusing needs
the fingerprint on the record, which is a contract release, and a rule for the
connections an agent opened before it renewed, which it counted as an agent
change, and neither was worth it while revoking the agent answers a key believed
copied.

INT-10 of the integration audit of 2026-11-09 measured the copy nobody believes
in. Thirteen seconds after `web-01` renewed, the certificate it had replaced had
a forged batch acknowledged and stored as `web-01`, and was handed the policy
and the update offer. A copy of the installation taken before the renewal
delivered eleven inventory records as the agent, and the matcher decided 171 of
the host's findings `removed`. At the default lifetime a replaced certificate
stays valid 42 to 70 hours.

What moved since: a decision reaches every gateway in milliseconds (ADR 46), a
gateway knows whether its roster is current, and the agent of `Seagull-agent-v2`
takes its certificate per handshake and closes its idle connections when the
certificate changes. Nathan confirmed BE-101 on 2026-11-21 knowing it reverses
ADR 46's deferral, and decided on 2026-11-23 that a gateway's refusals reach
BE-057 through `fleet-judge`.

## Decision

**The admission record names the certificate the registry binds an agent to, by
its fingerprint. A listener admits the agent on that certificate, admits the one
it replaced for a declared tolerance once it learns of the replacement, answers a
certificate newer than the one it holds so the agent sends again, and refuses
any other with a code of its own.**

### What the record carries

Contracts `v0.26.0` give `seagull.agent.v1.Admission` the fingerprint of the
certificate in force and the instant it is valid from, and the fingerprint of
the certificate it replaced and when it was bound; never a certificate or what it
names. For a renewal the replaced certificate is the one the renewal was
presented with, which an agent whose answer was lost still holds: a renewal asked
again (ADR 25's exception) replaces a certificate nobody received and tolerates
the one the agent has. For an operator's binding it is the one in force before.
A record without a fingerprint, for an agent nothing is bound to or written by a
platform older than the field, admits any certificate the authorities signed for
the agent, as before.

### How a listener judges

One rule, `agentidentity.Binding.Judge`, which the gateway's roster and the
control plane's agent listener both apply:

1. the certificate in force is admitted;
2. the certificate it replaced is admitted until the tolerance has passed since
   the later of its replacement and the moment the listener learned of it;
3. a certificate valid from no earlier than the one in force, or one the record
   cannot order, is one the listener has not heard of yet: the gateway answers
   `503 roster_behind` with `Retry-After`, the agent keeps the batch and sends it
   again, as it does for a stale roster;
4. any other is refused, `403 agent_certificate_replaced`.

Every answer to a certificate other than the one in force says
`Connection: close`, and the gateway decides it again as the answer is written,
so a batch in flight when the renewal lands completes and its connection is not
used again: the agent's next request opens a connection on the certificate it
renewed into. Over HTTP/2, which the agent does not speak, the same header makes
the server send `GOAWAY` and close the connection once it is idle. That is the
rule for connections opened before a renewal that ADR 46 counted as an agent
change; the agent needs none.

The tolerance is `SEAGULL_GATEWAY_REPLACED_CERTIFICATE_TOLERANCE` and
`SEAGULL_CONTROL_API_REPLACED_CERTIFICATE_TOLERANCE`, a minute by default, 5
seconds to 10 minutes. The agent's handshake takes at most its connect timeout of
10 seconds, and a renewal's answer reaches it within milliseconds of the record
reaching the gateway. A gateway counts it from when it learned the record while
following the log, never from before the replacement; a record read back before
it serves starts none, since no connection to it predates the replay. The
control listener reads the registry, is never behind it, and counts from the
replacement.

The stale roster and the agent's state are answered first: a revoked agent is
told `agent_not_admitted` whatever it presents, and every answer an agent reads
on its certificate in force is the one recorded before (ADR 48).

### Where

The gateway judges every stream and its descriptor from the roster in memory, a
map lookup and never a store read (ADR 24). The control plane's agent listener
judges the policy, the update offer, the package and the descriptor from the
registry, one more read by key per request; renewal keeps its own rule (ADR 25,
ADR 57).

### What a refusal becomes

It is counted (`seagull_ingest_certificates_total{standing}`, the streams'
rejections by code, `seagull_control_agent_certificates_total{standing}` and the
routes' `replaced` outcome) and logged with the agent and the route, never the
certificate.

The control listener records it in `agent_replaced_certificates` as it records a
refused renewal (ADR 57): one episode per certificate in force, the route it was
last refused on kept in `use_route` (migration 13) and published as the finding's
`use`.

A gateway gathers its refusals per agent and certificate in force, at most 10,000
at once, beyond which they are counted and not kept, and publishes them every
second as `seagull.agent.v1.Refusal` on `security.agents.refusals`, keyed by the
agent, three partitions, kept a week. A refusal the backbone did not take is
published with the next. `fleet-judge` reads that log whole as it reads the
others, and makes the refusals of one gateway listener while one certificate is
in force one `replaced_certificate` finding, named by that certificate and the
listener and never naming it; it is decided again a minute after new refusals
and every day without, closes as `REBOUND` when the admission log binds another
certificate and as `NOT_ADMITTED` when the agent is no longer admitted. A refusal
under a certificate since replaced, or older than the admission in force, is
counted outdated. At a start the judge restores its open findings and counts only
refusals newer than what they held. ADR 57's "each deciding its own kinds"
becomes each deciding its own episodes: `control-api` the agent listener's, the
judge the gateways'.

### The record is written again on upgrade

The registry keeps the shape of the record the log was last told
(`published_format`, migration 13). The announcer writes again, a batch at every
sweep, every agent whose record the log holds in an older shape, outside the
count of outstanding decisions, so an upgrade raises no
`SeagullAgentDecisionUnpublished`. A gateway reads the same revision again with
the certificate; a record of a revision it holds without the certificate never
erases one, and two of one revision binding different certificates stop the agent,
as two deciding one revision differently do (ADR 24).

Renewal and an operator's issuance now tell the log at once, as every other move
does; until now the sweep carried them, since neither changed what a gateway
admitted.

## What this deliberately does not do

- **Revoke or disable.** The agent's state does not change, and the certificate
  in force keeps working.
- **Catch a copy before a renewal separates the two.** Both hold the certificate
  in force, and BE-057's sequences are the signal. Whichever renews first holds
  the identity; which installation is the real one is an operator's.
- **Refuse in the gap between the registry and the log.** A renewal the log has
  not heard of leaves a gateway admitting the replaced certificate until the
  announcer's sweep carries it, which ADR 46's alarm reports, and answering the
  new one so the agent sends again.
- **Tell at a gateway a certificate the registry never bound from a newer one.**
  Both are answered as not yet heard; neither delivers anything.
- **Keep what a gateway gathered across a crash.** At most a second of refusals
  is lost, and the next refusal is published.
- **Count exactly across a judge's restart.** A gateway's record published late
  and older than the judge's last decision is not counted again.

## Consequences

- Contracts `v0.26.0`: `Admission` fields 6 to 9, `Refusal`.
- [ADR 24](0024-an-agent-is-registered-by-the-control-plane-and-refused-by-the-gateway.md),
  [ADR 25](0025-the-platform-signs-the-identity-it-binds.md),
  [ADR 46](0046-a-revocation-is-enforced-within-the-bound-a-gateway-confirms-its-roster-by.md)
  and [ADR 57](0057-a-place-is-a-run-and-a-renewal-is-refused-before-it-is-signed.md)
  are amended.
- An older gateway ignores the fields and admits any certificate of the agent; a
  decision an older `control-api` publishes during a rolling upgrade carries
  none, and the agent is admitted on any certificate until its next decision.
- The agent's current release reads `403 agent_certificate_replaced` as an answer
  it does not know, keeps the batch and sends it again later, and
  `503 roster_behind` as a busy listener; neither loses a record. Telling its
  operator why delivery stopped is AG-007's and AG-009's.
- Seven answers an agent reads are recorded (ADR 48): the gateway's replaced and
  not-yet-heard answers and its descriptor's, and the agent listener's on the
  policy, the update offer, the package and the descriptor.
