# 32. A rollout opens a release to the agents of a tenant wave by wave, by a place each agent keeps, and pauses on what its agents report

## Context

[ADR 31](0031-an-agent-release-is-authorized-off-the-platform.md) made which
agent runs which release the platform's decision and left it at one agent at a
time: an `Assignment` names agents one by one. BE-059 and AG-033 ask for the
rest: **stable cohorts by agent, canaries, percentages, pause and resume, and an
update failure that stops a rollout without a platform outage stopping it.**

Three properties decide the shape. A cohort has to stay put: an agent reconnects,
renews its certificate and rotates its key without leaving the wave it was in,
or a rollout reaches agents nobody chose and the count of who moved means
nothing. A failure has to be told apart from silence: an agent that cannot reach
the platform has not failed a release, and a rollout that paused on an outage
would stop every time the network did. And the agent decides nothing new: it
already verifies every release against a catalog operators signed and reports
where its update stands, `seagull.agent.v1.Status.update`, with a failure that
keeps `UNREACHABLE` apart from `UNVERIFIED`, `INSTALLATION` and `UNHEALTHY`. A
rollout is therefore a decision about assignments and nothing an agent has to
verify, sign or understand.

## Decision

**A tenant has at most one rollout in force. It moves the tenant's agents, or a
list of them, to a release the newest catalog names, through ordered waves: a
canary names agents one by one, and a share reaches every agent whose place —
drawn from the rollout and the agent alone — is below it. The control plane
reads the status of the agents the open waves reach, opens the next wave once
the open one soaked with enough of them running the release, and pauses the
rollout once as many of them failed it as the rollout allows. A paused rollout
asks nothing of any agent.**

### An agent's place is the rollout's and the agent's, and nothing else

`seagull.update.v1.Wave` states it: the first eight bytes of the SHA-256 of the
rollout identifier, a zero byte and the agent identifier, big-endian, modulo
10,000. A wave of `percent` reaches the places below `percent` times 100. The
identifier of an agent is what its certificate proves and what the registry
names; a renewal keeps it and so does a new key, so an agent never changes waves
by anything it does, and an agent registered while a rollout runs takes its place
like any other. The rollout identifier is a UUID the platform draws, so two
rollouts reach a tenant's agents in different orders and no agent is always
first. The formula is in the contract rather than in this code, because a backend
release that changed it would move every agent of a rollout in flight.

### A wave opens on a gate, or on an operator

Each wave but the last has a `soak` and a `running` count: the next wave opens
once the open one has been open for its soak and at least that many of the
agents reached so far run the release, by the version their newest report gives.
A wave without a soak waits for an operator to advance the rollout. The last
wave reaches every agent of the rollout and opens nothing after it. Advancing,
pausing, resuming and aborting are an operator's changes, under `agents:write`
in the tenant, and each is refused when it does not apply to the rollout as it
stands.

### What counts as a failure is what an agent says went wrong with the release

`internal/agentupdate.Judge` reads one agent's newest report against the
release: an agent running the release counts as running; one that went back from
it, or whose update failed because the release did not verify, did not install
or did not run as it should, counts as failed; one that refused it counts as
unable to take it. One that could not reach the platform is on its way, like one
that has not asked yet. The checks an agent makes before installing are made
before asking it, from what it reports of itself — whether it takes updates, how
it installs them, the generation of state it keeps — and from what the release
and the release it runs say, so an agent that cannot take the release is counted
as such rather than waited for. An agent assigned a release one by one is left to
that assignment and counted apart.

Once the agents failing the release reach the rollout's `failures`, the control
plane pauses it. A failure counts whenever it was reported, before the rollout
started included, because an agent that went back from a release does not try it
again under the same catalog. Resuming a rollout takes the agents the platform
last read as failing as known; a failure it reads afterwards counts again.

### The platform reads the agents it reached, and moves a rollout only on what it read

A component of `control-api` reads every rollout in force at start and every
`SEAGULL_CONTROL_API_AGENT_ROLLOUT_INTERVAL`: the agents of the tenant the
registry still listens to, those the open waves reach, and the newest report of
each from the status store, a thousand at a time. What it read is written with
the rollout, as its progress, and so is the set of agents it read as failing.
A reading is written only while the rollout stands where it was read — its state
and wave changed as many times as when it was read — so an operator's change made
meanwhile is never undone by it, and several control planes reading at once are
ordered the same way. A status store or a registry it cannot read costs that
reading and moves nothing.

### What an agent is asked to run

An agent asking whether to update is handed, as `Offer.version`, the release
assigned to it one by one, or else the release of its tenant's rollout while that
rollout is active and an open wave reaches it, or else nothing. It is handed a
package under the same rule. Starting a rollout takes over from the one in force,
under the same tenant lock an assignment takes; one that took over or was aborted
asks nothing of anybody again.

## What this deliberately does not do

**No groups.** The registry has none; a rollout reaches a tenant or a list of
agents. Rolling out by group waits for groups to exist (BE-058 scopes policies by
them too).

**No minimum supported version.** Which agent releases a backend release supports
is BE-056's.

**No automatic rollback.** A paused rollout leaves every agent on what it runs.
Going back from a release is a rollout to a release that `replaces` it, which
operators sign as a newer catalog, as ADR 31 says.

**No attestation.** Every count is of what agents say of themselves. An agent that
lies that it failed pauses a rollout sooner, which is the side a lie can push it
to; one that lies that it runs a release opens a wave sooner, which is what the
soak and the count of failures exist to hold.

## Consequences

- **`control-api` gains four operator routes, a setting, three tables and a
  component.** `POST /v1/agents/update/rollouts`, `.../rollouts/changes`,
  `.../rollouts/search` and `GET .../rollouts/{tenant}/{rollout}`; the evaluator
  runs only where an update root is configured.
- **A rollout's progress is as fresh as the status the agents report.** An agent
  reports every `reporting.interval` it chose, and the control plane reads every
  rollout interval, so a canary that went back from a release pauses a rollout
  within about the sum of both.
- **A failure reported before a rollout started pauses it.** Starting a rollout
  of a release some agents already went back from pauses it at once; an operator
  who knows those failures resumes it past them.
- **Agents asking whether to update cost one more join.** The rollout in force is
  read with the agent's assignment, and its waves are small enough to read on
  every request.
