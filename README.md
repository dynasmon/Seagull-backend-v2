# Seagull v2

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Backend](https://img.shields.io/badge/backend-Go%201.25-00ADD8.svg)](go.mod)
[![Backbone](https://img.shields.io/badge/backbone-Redpanda-E7407A.svg)](deploy/compose.yaml)
[![Store](https://img.shields.io/badge/store-ClickHouse-FFCC01.svg)](internal/clickhouse)
[![Contracts](https://img.shields.io/badge/contracts-Seagull--contracts-00A6A6.svg)](https://github.com/dynasmon/Seagull-contracts)

Seagull v2 is the backend of an open security operations platform, rebuilt as a
set of small processes around a durable event backbone. Telemetry becomes
durable before anything else happens to it; every capability downstream is a
consumer of that stream rather than a step inside the request that admitted it.

It is a re-architecture of [Seagull v1](https://github.com/dynasmon/Seagull), not
a port of it. v1 is the functional reference — its detection content, security
invariants and operational lessons carry over — while the layering, the queues,
the ORM-shaped domain and the synchronous telemetry path do not. Where the two
disagree, v2 wins unless there is evidence the v2 decision is wrong.

Endpoint collection is performed by an agent released independently, and the
messages the two exchange live in
[Seagull-contracts](https://github.com/dynasmon/Seagull-contracts) so that
neither repository depends on the other.

## What the backend does

### Durable telemetry ingestion

The gateway terminates mutual TLS, takes the agent's identity from the verified
certificate rather than from anything the producer sent, admits or refuses the
batch against explicit size and rate ceilings, and answers only once the
backbone owns it. An agent may drop its local copy of a batch on that answer and
on nothing else, so a gateway that crashes mid-batch costs a retry rather than
telemetry.

### Detection engineering

A rule names the class of event it reads and matches with a typed expression
over the fields of the event contract — there is no dictionary between the two,
so a rule naming a field the contract does not declare is refused where it is
written, with the line and the part that is wrong. Rules carry severity, ATT&CK
technique, false-positive guidance and provenance, and each one travels with the
cases it was written for, which the same evaluator checks.

### Incidents and correlation output

Event, detection, alert and incident are four records with four owners, not four
names for one row. A detection states that a rule matched; an alert is one
detection somebody owns; an incident is what a correlation becomes when a person
has to answer for it, named by the detection that told the story and carrying one
event per stage, so it can be traced back to what it was made of. It has a
lifecycle of its own and nothing an operator does to it writes to the events or
the detection behind it. How far the platform vouches for the order a story rests
on is measured from the clocks that timed it rather than declared by the rule.

### Ruleset management

Rulesets are administered through the control plane and published to a compacted
topic, never by reaching into a running engine. A ruleset is named by its own
content, so publishing the same rules twice is one version; publishing and
activating are separate acts, so a rollout can be rolled back to a version that
cannot have changed underneath it. Nothing that fails to compile, or whose own
cases do not hold, is ever written.

### Event hunting

The query plane holds the only read connection to the store, consumes no topic
and writes nothing. A query is a scope, a window and a question, and only the
last comes from the caller: the tenants a caller may read are derived rather
than requested, so a question cannot widen its own answer.

### Access control

The control plane authenticates by certificate, exchanges a completed handshake
for a short-lived session bound to that certificate, and decides every request
against a policy of typed permissions resolved per request. A token carries
identity and no authority. Every route declares what it requires and a route
that declares nothing cannot be registered, so deny-by-default is structural.

### Storage and failure semantics

Storage is owned per workload: ClickHouse holds telemetry and detections in
tables shaped for the questions asked of each. A consumer advances its position
only after the work it did is durable, so a crash replays rather than skips. A
record that can never be stored is quarantined with the reason and its position,
so one poison record cannot hold up a partition.

## Architecture

```text
Seagull Agent
      │  mutual TLS · protobuf
      ▼
 ingest-gateway ─────▶ Redpanda  security.events.raw
                           │  (durable before the acknowledgement)
             ┌─────────────┴─────────────┐
             ▼                           ▼
       event-writer                analysis-engine
             │                     route · normalise · detect
             ▼                           │
  ClickHouse security_events      security.detections
             │                           │
             ▼                 ┌─────────┴─────────┐
 security.events.quarantine    ▼                   ▼
                        detection-writer      alert-writer
                               │            above a severity floor: a finding
                               ▼            becomes an alert, a story an incident
                  ClickHouse security_detections   │
                                                   ▼
                     PostgreSQL alerts · incidents · trails · occurrences
                                                    ▲
 control-api ───────────────────────────────────────┘
   │   open · acknowledged · in investigation · resolved / false positive
   │
   └───▶ Redpanda security.rulesets ──▶ analysis-engine
         compiles, tests and publishes   compacted: every version,
         a ruleset; activates one        one pointer at the one to run

 query-api ──▶ both ClickHouse tables, read only, within a scope
```

Processes are declared in [`deploy/compose.yaml`](deploy/compose.yaml):

| Process | Role |
|---|---|
| `ingest-gateway` | The only durable entry point for telemetry: identity, admission, validation, rate limiting. |
| `analysis-engine` | Reads the event stream under its own group, routes and normalises, and decides events against the ruleset it is pinned to. |
| `event-writer` | Makes admitted telemetry queryable, quarantining what it cannot store. |
| `detection-writer` | Makes a detection queryable, on the same terms and as a consumer of its own. |
| `alert-writer` | Opens the work a detection at or above a severity floor becomes: an alert for a finding about one event, folded on a declared key, or an incident for a story several events told. It inserts and never updates. |
| `control-api` | The administrative surface: sessions, authorisation, ruleset validation, publication and rollback, and the alert and incident lifecycles. |
| `query-api` | The read plane, and the only reader of the analytical store. |
| `backbone-migrator`, `store-migrator`, `alert-migrator` | Apply the topic topology, the analytical schema and the relational schema, then exit. Nothing migrates on the way to serving traffic. |

Dependencies point one way — `cmd` → capability → domain, with adapters plugged
in at the edges and `internal/platform` never learning about the product. That
is not a convention: [`tests/architecture`](tests/architecture) enforces it, so a
violation fails the build rather than a review.

Two capabilities never reach each other through Go. They meet on the backbone,
which is what keeps the shape of an alert table out of the thing that decides
what an alert is about.

An alert is named by the detection that raised it, so a replayed batch finds the
alert it already opened rather than opening a second one — and the process that
opens alerts never updates one, so nothing a reprocessed batch does can reach
somebody's triage. [ADR 16](docs/decisions/0016-an-alert-is-a-detection-somebody-owns.md).

Noise is removed from the alert plane and never from the detection stream:
detections that are the same piece of work fold into one alert with a count,
the estate can declare which never become work at all, and both are counted so
what was reduced is readable. The detection keeps its full evidence for 730 days
whatever happens, and an alert names every detection it is made of.
[ADR 17](docs/decisions/0017-noise-is-removed-from-the-alert-and-never-from-the-detection.md).

What a rule remembers between events is a bounded window of the backbone, keyed
by tenant, rule, revision and group, and measured in event time. State is a pure
function of the events inside its window, so a replayed batch counts once and a
restart rebuilds it by reading the window again rather than by recovering
anything. Every ceiling is declared, and a store at its limit refuses a new key
instead of evicting one: a flood of invented group values must not get to choose
which real counts an estate forgets.
[ADR 18](docs/decisions/0018-detection-state-is-a-bounded-window.md).

A rule may count what it matches: twenty failed passwords from one address
against one agent inside a minute is a different security statement from one
failed password, made of the same match. The count is part of the rule rather
than a second kind of rule, every window is event time, and the detection
carries what was counted — how many, against which threshold, over what window,
and what the events shared — so a threshold finding is not mistaken for a single
event. Nothing resets when a rule fires: past its threshold a rule decides once
per event and never more, and `deploy/alerting.yml` is where those become one
piece of work.
[ADR 19](docs/decisions/0019-a-rule-that-counts-decides-on-a-window.md).

A rule may instead order what it matches: a failed SSH password from an address,
then one from the same address that was accepted, inside five minutes, is a guess
that worked — where either event alone is unremarkable. The stages are what such
a rule matches with, so it carries a sequence or a match and never both, and the
match of each stage stays a pure function of one event while the order is read
out of the same bounded window a count is. Ordering is event time, which means
the story does not depend on the backbone delivering it in order: an event that
arrives after a later stage lands where it happened and is what completes the
story. The detection names the event that satisfied each stage, so an incident
can be traced back to the events it was made of, and it carries how far apart the
clocks that timed them stood — because ordering rests on the producer's clock,
and a story whose clocks disagree by more than it lasted is one the data does not
order.
[ADR 20](docs/decisions/0020-a-sequence-is-decided-by-the-window-that-holds-it.md).

A story that several events tell is a different piece of work from a finding
about one of them, so a detection carrying a correlation opens an incident and
never an alert. It is named by that detection the way an alert is named by the
one that raised it, so a replay finds the story it already opened; it carries one
event per stage and the group that made them one story, so the trace to its
component events and detection is on the record rather than in a join; and it has
a lifecycle of its own, granted separately, whose moves never touch what the
analysis engine wrote. How far the order can be trusted is a measurement rather
than a number somebody tuned: the spread of the clocks that timed the story,
against its own span and against the window the rule looked through.
[ADR 21](docs/decisions/0021-an-incident-is-a-correlation-somebody-owns.md).

## Getting started

Requires Docker with the Compose plugin and Go 1.25.

```bash
make dev-pki    # mint a development CA, server, agent and caller certificates
make up         # build the images and start the backbone, the store and every process
make verify     # the full gate: lint, module graph, tests, race detector
```

`make up` writes nothing outside the repository and reads nothing that is not in
it; the development material lands in `.local/pki`, which Git ignores.

Send a batch through the running gateway, then ask the query plane what became
of it:

```bash
go run ./tools/devprobe -endpoint https://127.0.0.1:8443
go run ./tools/devprobe -hunt https://127.0.0.1:8444
```

Stop everything and drop its state with `make down`. If a port is taken, publish
elsewhere with `SEAGULL_GATEWAY_PUBLISH`, `SEAGULL_QUERY_API_PUBLISH` or
`SEAGULL_CONTROL_API_PUBLISH`.

## Configuration

Every setting is an environment variable, typed, validated at startup, and
reported all at once when something is wrong. Any variable can be read from a
file instead by adding the `_FILE` suffix, which is how secrets reach a
container without going through the environment. The settings that matter most:

| Variable | Purpose |
|---|---|
| `SEAGULL_BACKBONE_BROKERS` | The event backbone every process depends on. |
| `SEAGULL_GATEWAY_TLS_CERT`, `SEAGULL_GATEWAY_TLS_KEY`, `SEAGULL_GATEWAY_AGENT_CA` | The gateway's mutual TLS material; there is no plaintext mode. |
| `SEAGULL_TENANT_ID` | The tenant the gateway stamps on everything it admits. |
| `SEAGULL_DETECTION_RULES` | The rule tree the engine starts on and falls back to. |
| `SEAGULL_DETECTION_STATE_WINDOW`, `SEAGULL_DETECTION_STATE_OBSERVATIONS`, `SEAGULL_DETECTION_STATE_KEYS` | What a counting or ordering rule may remember: the longest window, the events one key holds, and how many keys at once. |
| `SEAGULL_CONTROL_API_POLICY` | The policy document the control plane is pinned to. |
| `SEAGULL_CONTROL_API_SESSION_KEY` | Key sessions are signed with; drawn at random when unset. |
| `SEAGULL_EVENT_STORE_ADDRESS`, `SEAGULL_EVENT_STORE_PASSWORD` | The telemetry store and its credentials. |

[`docs/configuration.md`](docs/configuration.md) lists every setting each
process reads, along with the acknowledgement contract, the topic topology and
the shape of the store.

## Tests

```bash
make test              # unit, architecture and end-to-end suites
make test-race         # the same suites under the race detector
make test-integration  # the data plane against a live Redpanda and ClickHouse
make test-load         # the ingest load scenarios against a live Redpanda
make bench             # the hot path, one core, no infrastructure
```

The end-to-end suite mints its own certificate authority and drives the real
listeners over real mutual TLS, so it depends on no fixture files and no
property of the machine it runs on. The integration suite ends with the whole
slice — admission, backbone, writer, store — against real infrastructure, which
is what the rest of it is a decomposition of. The load suite fails a run when
the gateway allocates more than 8 KB per admitted event, when a slow backbone
produces an acknowledgement the backbone never received, or when a shutdown
drops a batch it had already answered for.

## Further reading

| Document | Topic |
|---|---|
| [Architecture decisions](docs/decisions) | Why the foundation looks like this, one record per decision. |
| [Configuration reference](docs/configuration.md) | Every setting, the acknowledgement contract, the topology, the store. |
| [Seagull-contracts](https://github.com/dynasmon/Seagull-contracts) | The messages agents, the platform and the portal exchange. |

Agent enrollment and registry, inventory, vulnerability matching, response
actions and Sigma import are not implemented. Detection is stateless unless a
rule asks otherwise: a rule that counts or orders its events reads a bounded
window of the backbone in event time, which is what keeps both replayable.

## License

Seagull is licensed under the [GNU General Public License v3.0](LICENSE).
