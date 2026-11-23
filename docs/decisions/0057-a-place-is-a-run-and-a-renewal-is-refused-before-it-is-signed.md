# 57. A place is a run: a copy reports a sequence another run already holds, a shared identity is two installations heard in turn, and a renewal is refused before it is signed

## Context

[ADR 56](0056-a-finding-about-an-agent-is-a-record-of-its-own-judged-only-while-the-platform-listens.md)
made a finding about an agent a record of its own and built the first kind,
silence. It gave the duplicate-identity kinds one sentence each — a run reporting
a sequence its installation had already passed, two installations writing new
reports in turn, a renewal asked with a certificate a renewal had replaced — and
left what they are judged from to the next part of BE-057.

The integration audit of 2026-11-09 is what they have to catch. INT-10 copied an
agent's state directory to a second machine after the original renewed: the copy
was refused its own renewal, went on delivering as the agent, and nothing told an
operator. INT-12 found that the renewal route signs before the registry decides,
so a refused renewal spends a signature and a serial number.

A report already carries what tells two places apart: the installation, a
sequence the agent makes durable before it sends the report carrying it and never
reuses, the boot, when the run started, when the run before it was last seen,
when the agent wrote it, and when the platform received it. A report sent again
is the same bytes under the same sequence (`Seagull-agent-v2/internal/reporting`),
so one source never writes one sequence twice.

## Decision

**`fleet-judge` tells the places an agent reports from apart by run. A copy is a
run reporting a sequence another run of its installation already holds and did
not account for; a shared identity is two installations writing new reports in
turn. `control-api` asks the registry before it signs a renewal, and keeps every
episode of a replaced certificate presented again beside the certificate trail,
which it publishes as a finding.**

### Places

A place is one run of one installation: its installation, its boot and when the
run started. For each agent the judge holds at most four, each with its report of
the highest sequence, its newest report, and when its run says the run before it
was last seen. A place not heard for its silence threshold, five intervals of its
newest report, is forgotten, judged at the ingest time of the report being read,
so reading the log back forgets what the live judge forgot. A fifth place takes
the slot of the one heard longest ago.

### A copied installation

A report is evidence of a copy when another place of its installation, still
held, already holds a sequence at least as high, and the report is not one that
place's run accounted for. A report is accounted for when its run started before
the other place's run, and it was written no later than the later of that run's
start and the moment it says the run before it was last seen: it is late, not
copied. A report of its own run with a sequence below the run's highest is late
too, since a run counts upwards and a report sent again is the same report.

The episode is the installation and the sequence of the first report heard
twice. Every later report that is evidence for it is an observation; the finding
names the newest report of each run, at most four.

### A shared identity

A report of an installation is a turn when that installation was heard before, the
report carries a sequence above any it reported, another installation the judge
holds wrote its newest after this one's, and the report was written after that
other installation's run began. Each report is judged by when it was written, so
a report the replaced installation sent before it stopped, and that arrived late,
takes no turn; an installation heard for the first time takes none either, so a
reinstalled agent is not a shared identity. The episode is the two installations,
sorted, so whichever took the turn names the same finding. A shared identity that
closed is kept, at most four, so the same two installations taking turns again
open it again under its name and its first opening.

### One source

An open copy or shared identity closes as `ONE_SOURCE` once exactly one of the
places it names is still heard within its threshold and every other one stayed
away its own threshold while the platform listened, the stretch ADR 56 confirms
for silence. It closed at the latest instant one of the others had stayed away
that long. It closes as `NOT_ADMITTED` when the registry stops admitting the
agent, as a silence does.

A finding observed again is decided again once a threshold of its newest evidence
has passed since its previous decision, and an open one with nothing new every
day, as ADR 56 decides every open finding.

### Bounds

At most four places, four reports per finding, four open findings of each kind
and four closed shared identities per agent. An episode found while its agent
already holds four open findings of its kind is counted in
`seagull_fleetjudge_findings_not_opened_total{kind}` and not opened. A holder of
the key choosing installations and runs at will costs the judge a constant per
agent: an identity reported from that many places is already the operator's to
answer, and revoking it closes every finding at once.

### Replay and restart

Copies and shared identities are decided from live reports only. At a start, the
judge restores its open copies and shared identities, and its closed shared
identities, from its own decisions before it reads the status log back; reading
it back observes, for an open finding, only reports newer than its last
observation, so a restart counts once what arrived while no judge ran and opens
nothing new. One whose agent is no longer admitted is closed as `NOT_ADMITTED`.

### A replaced certificate, decided by `control-api`

The renewal route names the request the way signing would — parsed, its subject
checked, its digest taken — and asks the registry, under the agent's row lock,
whether binding it would be refused, before the authority signs anything. Asking
and binding apply one rule, `agent.Renewing`, so they cannot disagree. A renewal
the registry refuses spends no signature and no serial number, and the agent is
answered as before ([ADR 48](0048-every-answer-an-agent-reads-is-recorded-here-and-changes-only-by-a-version-decision.md)).
Two renewals presented with one certificate at once are still decided at binding,
and the one that loses is recorded the same way.

A renewal refused as already replaced is recorded in the transaction that decided
it, in PostgreSQL `agent_replaced_certificates`: one row per agent and certificate
in force, which is the episode, with when it opened, when it was last observed,
how often, and how it closed. A move that binds another certificate closes it as
`REBOUND`, and one that stops admitting the agent as `NOT_ADMITTED`, in that
move's transaction. The certificate in force names the row and never leaves the
platform: the finding is named by a digest of it, says it was used on the control
listener at `POST /v1/agents/certificate`, and names no certificate, and the log
line names the agent alone.

`control-api`'s `agent-finding-announcer` hands the findings log what the
registry decided and the log was not told, oldest first, every
`SEAGULL_CONTROL_API_ANNOUNCE_INTERVAL`, as the agent announcer hands the
gateways their admissions
([ADR 46](0046-a-revocation-is-enforced-within-the-bound-a-gateway-confirms-its-roster-by.md)):
the registry is written first, so a decision the log did not take is published
again rather than lost. An open one is decided again every day. `control-api`
never reads the findings log back; its decisions are the registry's. The log has
two writers, each deciding its own kinds, and the judge reads back none of
`control-api`'s.

## What this deliberately does not do

- **Find two sources within one run.** A host whose memory is cloned while the
  agent runs, a live clone or a memory snapshot resumed elsewhere, goes on as the
  same run, with the same boot and the same start, and is one place to the judge:
  its reports read as late reports of that run. Telling the two apart needs a
  place the reports do not name, and a closure the judge cannot judge, since one
  source is counted in places. The certificate is what catches it: the first of
  the two to renew replaces the certificate the other holds, whose own renewal is
  then refused as replaced, and BE-101 adds the listener.
- **Say which installation is the real one.** Revoking the agent and enrolling it
  again is the operator's answer, as ADR 56 says.
- **Decide a copy again once it closed.** Another copy of the same installation
  starts at another sequence and is another finding.
- **Find a replaced certificate at a listener.** That is BE-101.

## Consequences

- `control-api` writes `security.agents.findings`, verifies it at start and
  reports its durability, and the control store gains migration 12.
- A renewal reads the registry twice, each time under the agent's row lock: once
  before it is signed, once to bind it.
- `seagull_control_agent_certificates_renewed_total{outcome="replaced"}`,
  `seagull_control_agent_findings_published_total{outcome}` and
  `seagull_control_agent_findings_outstanding` count what `control-api` decides
  and carries; `seagull_fleetjudge_open_findings{kind}` counts the judge's copies
  and shared identities beside its silences.
- ADR 56's "a decider reads its own decisions back" holds for the judge;
  `control-api` keeps its decisions in the registry.
