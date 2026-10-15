# 33. An assessment is a record of its own, and an agent's posture is its newest assessment of the checks an operator signed

## Context

BE-060 asks the platform to admit, keep and answer security configuration
assessment results: an agent runs posture checks against its own host — the
permissions of a file, a kernel parameter, whether a package is installed or a
service enabled, a directive sshd applies — and the platform holds what they
found per asset. Three properties of that work decide how it travels.

Who decides what is checked decides what a passing posture means. A check
supplied by whoever can write to the agent's host, or by the platform itself,
would let either make a weakened host look hardened. The signed agent policy
([ADR 29](0029-an-agent-policy-is-signed-off-the-platform.md)) already carries
what an operator decided, signed with a key the platform does not hold.

A check is not a command. A remotely supplied check that runs a program is
remote code execution with extra steps, and its output is whatever that program
prints. What a check may read has to be typed and bounded where it is written,
and checked where it is published as well as where it runs.

What a posture was matters as much as what it is: when a host became weaker is
an investigation's question, and an agent offline for a week has a week of
changes to report. A record that only keeps the newest would lose the history
the agent kept for it.

## Decision

**A checklist travels inside the signed policy, as typed checks with bounded
parameters, and the platform holds it to the contract when the policy is
published. What an agent found is an assessment — a record of its own, admitted
behind the same gate, published to a topic of its own keyed by the agent,
kept by a process of its own one row per assessment — and an agent's posture is
its newest assessment, carried when one agent is read.**

### What is checked is signed off the platform

`seagull.policy.v1.Settings.assessment` is a `seagull.assessment.v1.Checklist`:
up to 512 checks, each named by an identifier and carrying exactly one test — a
path's metadata, the host's account files, a kernel parameter or module, a
package, a service unit, a directive of sshd or login.defs. No test runs a
command and none reads more of a file than the directive it names. An agent's own
configuration names no checks, so what an agent assesses is always what an
operator signed, under the revision every result names.

`agentpolicy.Validate` holds every check to `assessment.ValidateChecklist` when a
policy is published, and refuses the policy naming every check that is wrong —
an empty checklist, a path within /proc, /sys, /dev, /run, /tmp or /var/tmp, a
check that judges nothing, bounds no value lies between. An agent built against
an older contract answers a check it cannot read whole as unsupported instead of
refusing the policy, so the platform's check is where a mistake is caught for
every agent at once.

### The gateway admits it behind the same gate

`POST /v1/assessments` is the fourth route of the gateway, behind the same
verified certificate, roster answer, rate limiter, capacity bound and body
ceiling, answered with the same `BatchAck` and `Rejection`, code
`invalid_assessment`. The gateway stamps the agent from the certificate, the
tenant from the roster and the reception from its own clock: a posture is
evidence about a host, and an agent that could file its findings under another
agent or estate could make a weakened host look hardened. An assessment is
admitted within its own window, `SEAGULL_ASSESSMENT_MAX_AGE` (720 hours), because
an agent keeps what it found until the platform holds it, as long as an
inventory scan.

### The topic and the table keep every assessment

`security.assessments` is keyed by the agent and cleaned up by retention, not
compacted: the newest assessment is the posture, and the ones before it are the
history the agent kept them for. `assessment-projector` keeps the topic in
ClickHouse `agent_assessments`, one row per assessment, a `ReplacingMergeTree`
ordered by `(tenant_id, agent_id, assessed_at, assessment_id)` and versioned by
`ingest_time`: the same assessment published twice — an answer the agent never
received, a replay — merges into one row. The row carries the assessment exactly
as the gateway published it beside its policy, its revision and how many of its
checks passed, failed, erred, were unsupported or did not apply. It is a failure
domain of its own: an assessment store outage costs how fresh a posture is, and
never the admission or the storage of telemetry.

### A posture is the newest assessment, by when the agent made it

`Agent.assessment` is the agent's newest assessment by `assessed_at`, read when
one agent is read and left out of a page, the way the newest status report is.
An assessment answers every check of the revision it names, so the newest one is
the whole posture, and a check it does not answer is one the policy no longer
asks for; one that answers nothing says the policy asks for no checks. A store
that does not answer costs the caller the posture and never the agent.

## What this deliberately does not do

**No scoring.** The platform keeps what each check found and counts outcomes; it
does not weigh a failure, turn a posture into a number, or raise an alert for one.
`unsupported`, `error` and `not_applicable` are never read as a pass.

**No third-party benchmark.** No checklist ships with the platform. Benchmark
content an operator brings is theirs to license; the contract carries checks,
not the text of a benchmark.

**No query across agents.** Which hosts fail a check, and since when, is
answerable from `agent_assessments` and is a later card's question; this one
carries the posture of one agent.

**No findings from drift.** An agent whose posture worsened raises nothing on
its own; BE-057 decides what the platform makes of an agent's changes.

## Consequences

- **Fourteen topics and one more process.** `security.assessments`,
  `security.assessments.quarantine` and `assessment-projector`, which the
  migrators, the images and Compose carry like the others.
- **A policy is a larger document.** A checklist of 512 checks fits the policy's
  1 MiB payload, and every one is validated on publish.
- **`Agent` grows one observed field**, read from `agent_assessments` through the
  telemetry store's connection when one agent is read.
- **The agent decides when it assesses**, between a minute and a day, and sends
  an assessment when its posture changed and at least once a day.
