# 31. An agent release is authorized off the platform by the roles of a root, and the platform decides only which agent runs which release

## Context

An agent installed on a host is the release somebody installed there. Moving an
estate to a newer release means reaching every host, and BE-059 asks for the
alternative: releases distributed by the platform and rolled out gradually, with
**an established signed-metadata design — roles, key rotation, expiry, rollback
protection — and a distribution endpoint that holds no signing key.**

An update is the most dangerous thing a platform can hand an agent. A policy
changes what an agent collects; a release replaces the agent, runs with whatever
privilege installs it, and decides everything afterwards. Whoever can make an
estate install a package owns the estate. The same reasoning as
[ADR 29](0029-an-agent-policy-is-signed-off-the-platform.md) applies with more
force: the key that authorizes a release has to be where taking the platform
does not reach it, and a single key is not enough, because a key that signs
releases is one an estate must be able to replace without reinstalling every
agent by hand.

The Update Framework is the established answer to both: a root role that names
the keys of every role and how many of them must agree, and moves to new keys
through a chain each step of which both the old and the new keys signed; a
targets role that says which artifacts are authorized; versions that only move
forward, so metadata cannot be replayed backwards; expiry, so metadata nobody
renewed stops authorizing anything. TUF also has a timestamp and a snapshot
role, signed online so clients learn quickly that metadata changed. BE-059 rules
out exactly that: no key at the distribution endpoint.

## Decision

**A release is authorized by a catalog signed by the catalog role of a root the
platform holds no key of. The platform verifies both, keeps them with the
packages they name, and hands an agent the roots, the newest catalog and the
version it wants that agent to run; the agent verifies everything again and
installs only what the catalog allows.**

### Two roles, after TUF, and no online role

`seagull.update.v1.Root` names keys and two roles — the root role, which signs
the next root, and the catalog role, which signs a catalog — each with a
threshold. A `Catalog` is TUF's targets role: every release agents may install,
one entry per package and platform, with the digest and size of the package, the
revision it was built from, the oldest version it may be installed over, the
generation of local state it keeps, and the later versions it may replace when
it is how an operator goes back. Both travel as DSSE envelopes, ECDSA over P-256
on DSSE's pre-authentication encoding, as the agent policy does, so a verifier
checks every signature before it decodes anything.

There is no timestamp or snapshot role. A single catalog lists everything, so
there is nothing for a snapshot to keep consistent, and a catalog's expiry is the
freshness an agent relies on: an operator signs a new catalog before the one in
force runs out, and an agent installs nothing under a catalog or a root that ran
out. That is slower to learn of a withdrawn release than an online timestamp
would be, and it is what holding no key at the endpoint costs.

### The root moves only through its chain

`control-api` is configured with a root, as a file named by
`SEAGULL_CONTROL_API_AGENT_UPDATE_ROOT` and read again whenever it is needed; the
same root is provisioned on every agent out of band, beside its trust in the
platform. A newer root is published through the platform and recorded only as
the next version, signed by a threshold of the previous root's root keys and a
threshold of its own — TUF's rule, so a rotation is vouched for by the keys it
retires. Rotating or revoking a key is publishing the next root without it. A
root that ran out still leads to the next one; only the newest root an agent
reaches must be in force.

### What may be installed is signed, and who installs it is decided

A catalog says what may be installed, and nothing in it names an agent. Which
agent runs which release, and when, is the platform's decision: an `Assignment`
points agents of a tenant at a version the newest catalog names, by whoever may
change agents there, and is never signed. That is what lets a rollout move — a
canary, a percentage, a pause in AG-033 — without anybody signing anything, and
it costs what it says: a taken control plane can withhold an update or move an
agent to another release the newest catalog still authorizes. It cannot move an
agent to anything an operator did not sign, nor back past what a release allows:
an agent refuses an older release unless that release names the one it runs in
`replaces`, and refuses a catalog older than the newest it verified.

### The platform keeps packages and hands them only to agents assigned a release

A package is given to the platform by its bytes and kept by its digest, trusted
for nothing: an agent checks every byte against the catalog before anything
installs it. A catalog naming a package the platform was not given is refused,
so nothing an agent is told to install is missing. An agent asking for a package
is handed it only while the newest catalog names it and the agent is assigned a
version that catalog names: the release it is to run, and the release it runs,
which its installer goes back to when the new one does not run. It is handed
over the listener the agent renews on, with no redirect and no other host to
reach, by as few agents at once as the process can hold in memory.

### Versions only move forward, decided under a lock

Roots, catalogs and assignments are each recorded inside a transaction holding a
lock of their own, so two publications racing are ordered: the second is
compared with what the first recorded. A root is refused unless it is the next
version, a catalog unless it exceeds the newest, an assignment unless the newest
catalog names its version and every agent it names is registered in the tenant.

### An agent says how its update goes on its status

`seagull.agent.v1.Status` carries `update`: the stage an update reached, the
version, the catalog and root behind it, and a failure that keeps an update that
went wrong apart from a platform that could not be reached. The gateway holds it
to its bounds like every other field; the store keeps the report whole, so it is
read back with the rest.

## What this deliberately does not do

**No rollout.** An assignment names agents one by one. Cohorts, percentages,
canaries and pauses are AG-033 and the rest of BE-059; they decide assignments
and change nothing an agent verifies, as
[ADR 32](0032-a-rollout-opens-a-release-wave-by-wave-and-pauses-on-what-agents-report.md)
decides.

**No compatibility window.** Which agent releases a backend release supports is
BE-056's.

**No building.** The platform distributes packages built and attested elsewhere
— the agent's release workflow attests each one — and an operator verifies that
attestation before signing a catalog naming the package.

**No signing service and no key management API.** `tools/updatesign` signs a root
or a catalog with keys held wherever an estate keeps them; the platform is given
signed metadata and public keys inside it, never a private key.

**No audit store.** Every publication and assignment is logged with who made it;
the tamper-evident trail is BE-039's.

## Consequences

- **`control-api` gains a setting, five tables, four operator routes and two
  agent routes.** Without the root it takes no update and says so, and tells an
  agent asking that it hands out none.
- **An estate needs keys held off the platform**, at least one per role, and the
  discipline that comes with them: a catalog must be signed again before it runs
  out, and a root at least once a year.
- **A taken control plane can freeze an estate on the releases it runs**, and
  that is visible: a catalog that is not renewed runs out, and agents stop
  installing anything rather than installing something old.
- **The store holds packages**, up to 256 MiB each, as rows; a deployment that
  distributes many releases sizes its database for them.
