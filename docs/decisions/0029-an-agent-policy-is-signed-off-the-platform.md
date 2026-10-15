# 29. An agent policy is signed off the platform, and an agent is handed the newest revision of its tenant that names it

## Context

An agent runs on the configuration file somebody wrote on its host. Changing how
an estate collects — which modules run and how often, what the files module
watches, how much an agent may spend — means reaching every host, and BE-058
asks for the alternative: a policy managed centrally, applied within a baseline
the host protects, and **signed by a trust separate from mutual TLS.**

That last clause is the whole design problem. The agent already authenticates the
control plane by certificate, so a policy the control plane signed for itself
would prove only what the TLS handshake already proved: that it came from the
control plane. Whoever took the control plane would hold the key and could tell
every agent to stop collecting, which is the most useful thing an intruder can
say to an estate's sensors.

[ADR 25](0025-the-platform-signs-the-identity-it-binds.md) placed the agent
certificate authority in `control-api` because the process deciding who may have
a certificate is the one already trusted to decide it, and a separate signer
would have been reached with credentials weaker than the ones protecting the
plane. A policy is different in kind. A certificate admits an agent to the
platform; a policy changes what the agent does on its host, and nothing on the
agent checks it again except the signature. The key that signs one has to be
where taking the platform does not reach it.

[ADR 15](0015-a-ruleset-is-published-to-a-log.md)'s pattern — every version kept,
one pointer naming what runs, rollback as a pointer move — is what BE-058 names
for storing policies. It fits rulesets because the platform runs what it points
at. An agent does not run what the platform points at: it runs what it verified,
and refuses anything older than what it already holds.

## Decision

**A policy is signed by whoever administers the estate, with a key the platform
never holds. The platform verifies it, records it, and hands each agent the
highest revision of its tenant that names it; the agent verifies it again and
applies it within its own configuration.**

### The signing key is held off the platform

An operator signs a policy where they write it — `tools/policysign` does it with
a PEM key — and publishes the result. `control-api` is given only public keys,
in a file named by `SEAGULL_CONTROL_API_AGENT_POLICY_SIGNERS` and read again for
every publication, the way the trust bundle is read for every issuance, so adding
a signer or retiring one is a file write. A publication no listed key signed is
refused, so nothing an agent would refuse is ever distributed. Every agent is
provisioned with the public keys it accepts out of band, like its trust in the
platform, and checks the signature again: publishing and applying are checked
independently, and neither trusts the other.

A control plane somebody took can therefore withhold what an operator signed,
and stop answering; it cannot write a policy, and it cannot change one without
every agent refusing it.

### The envelope is DSSE

`seagull.policy.v1.SignedPolicy` is a DSSE envelope with DSSE's own field names
and numbers: the payload is a serialized `Policy`, and the signature — ECDSA over
P-256 — covers the payload type and the payload bytes exactly as they travel. A
verifier checks it before decoding anything, so a payload nobody signed is never
parsed and nothing has to be re-encoded to be checked, and the payload type in
the signature keeps a policy signature from standing for anything else the same
key signs. An established envelope also means the JSON form of what crosses the
wire is one DSSE tooling already reads.

A policy holding a field the platform does not know is refused at publication,
because a setting the platform cannot validate is one it cannot promise an agent
will take.

### Revisions increase across a tenant, and the newest one naming an agent is the one it is handed

A policy names the agents it is for by the identifier each was issued, and every
one of them must be registered in the tenant it is published into. Its revision
increases across every policy of the tenant, whichever `policy_id` it carries:
the platform refuses a revision that does not exceed the highest the tenant
holds, deciding under a lock held for the tenant, so two publications racing are
ordered rather than both accepted. An agent asking is handed the highest revision
of its tenant that names it.

That is what makes the agent's own rule — refuse any revision lower than the one
it applied — sufficient. Moving an agent from one policy to another is a newer
revision naming it, so a platform replaying the older policy is refused; going
back to earlier settings is signing them again under a newer revision.

**Publishing is activating, and there is no pointer.** The signature is the
authorisation, and a pointer the platform could move back would point every agent
at a revision it refuses.

### A policy expires, and an agent keeps the last one it verified

`expires_at` is required and at most 366 days after `issued_at`, and a
publication already past it is refused. An agent refuses a policy that arrives
expired and keeps one that expires while in force, reporting it: an agent cannot
do better than the last policy it verified, and a running agent on an expired
policy is how a platform that stopped handing out newer ones is noticed.

### Policies live with the registry, and agents ask where they renew

The records are relational and person-owned, and each names registered agents,
so they live in PostgreSQL beside the registry, applied by `control-migrator`:
`agent_policies` holds every revision with the envelope it is served as and the
digest of it, append only, and `agent_policy_targets` the agents each names,
keyed so the newest revision naming an agent is read backwards from the agent.

An agent asks with `GET /v1/agents/policy` on the agent listener ADR 25
introduced — the same trust domain and the second route on it. The agent is read
off the verified chain, an agent the registry no longer admits is refused as its
renewal would be, and the answer carries the digest as an `ETag`, so an agent
that already holds the policy is told `304` and nothing travels. Requests are
limited per agent, like renewals.

Operators publish with `POST /v1/agents/policies`, list with
`POST /v1/agents/policies/search` and read one revision whole with
`GET /v1/agents/policies/{tenant}/{revision}`. Publishing needs `agents:write`
in the tenant; reading needs `agents:read`, within the tenants the caller holds.

### What a policy may set is a bounded subset, and it never raises a ceiling

The log level, which modules collect and how often, what the files module
watches and leaves out, and budgets. A budget lowers the ceiling the agent's own
configuration sets and never raises it, and nothing in a policy names the
platform, what the agent trusts, its identity or its timeouts. The contract
states every bound, the platform refuses a policy outside them, and the agent
refuses one whose configuration it would not run on. A policy also carries the
checks the agents it names assess their hosts against, which no agent's own
configuration names, as
[ADR 33](0033-a-posture-is-the-newest-assessment-of-checks-an-operator-signed.md)
decides.

## What this deliberately does not do

**No groups and no staged rollout.** BE-058 scopes policies by groups of agents
in the registry, and the registry has none yet. A target is a list of agent
identifiers; a group arrives as another kind of target, which an agent that does
not know it refuses whole.

**No record of what an agent applied.** The platform knows what it handed out,
not what each agent did with it; that is the status BE-053 admits.

**No audit store.** Each publication is recorded with who published it and when,
and logged as `agent_policy_published` with its tenant, revision, targets, digest
and signers. The tamper-evident trail is BE-039's.

**No signing service and no key management API.** The signer set is
configuration, as the authority set is in ADR 25: it changes when an estate
rotates a key, deliberately and rarely.

## Consequences

- **`control-api` gains a setting, two tables, three operator routes and one
  agent route.** Without the signers setting it publishes nothing and says so,
  and still answers agents, which are told no policy names them.
- **An estate needs a key held off the platform**, and the discipline that comes
  with it: whoever holds it decides how every agent of the estate runs.
- **A taken control plane can freeze an estate on its current policies**, and
  that is visible: an agent reports the policy it runs on once it expires.
- **The agent's own configuration still bounds every policy.** An estate that
  wants a host never to run a module, or never to spend more than a budget, says
  so on the host, and no policy changes it.
