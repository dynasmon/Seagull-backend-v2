# Seagull v2

A security event processing platform. Telemetry becomes durable on an event
backbone before anything else happens to it; the control plane is built around
that pipeline rather than the other way around.

This repository holds the foundation, the first vertical slice and the runtime
the analysis pipeline will be built inside: telemetry travels from an agent to a
queryable store, every step of it is durable, and a second consumer reads the
same stream, routes it and puts it into canonical form. Detection has a rule
model and nothing that evaluates it yet; correlation and the control plane are
not implemented.

## What runs today

```text
Seagull Agent
      |  mutual TLS, protobuf
      v
cmd/ingest-gateway  ── admission control ──▶  Redpanda  security.events.raw
      |                                             (durable before the ack)
      |                                              |                    |
cmd/control-api     ── protocol descriptor           v                    v
                                        cmd/event-writer      cmd/analysis-engine
                                                 |
                                                 ▼
                                    ClickHouse  security_events
                                                 |
                                                 ▼
                                       security.events.quarantine
```

`ingest-gateway` authenticates an agent by its client certificate, admits or
refuses the batch, publishes it to the backbone and answers only once the
backbone owns it. It holds no database, no cache and no analytics.

`event-writer` consumes the backbone and makes admitted telemetry queryable. It
advances its group position only after a batch is durable in the store, so a
crash replays a batch and never steps over it. A record it cannot store — one
that is not a `seagull.event.v1.Event`, breaks the contract, or carries an
instant the store cannot hold — is published to `security.events.quarantine`
and the rest of the batch continues, so one bad record can never hold up a
partition.

`analysis-engine` consumes the same topic under a group of its own, so it and
the writer advance independently and neither can hold the other back. It turns a
record into a `seagull.event.v1.Event`, routes it by the class it carries,
refuses what it cannot read without returning an error — one unreadable record
must never hold a partition — and reports how long after admission each event
reached it.

Routing decides before the contract does, and that order separates two failures
an operator answers differently. A class this build's contract does not declare
is reported as *unrouted*: the gateway validated the class before it admitted
the event, so the stream has moved ahead of the process reading it and the
answer is a deployment. An event that declares no class at all is refused as a
contract violation, because that producer is broken. Every class the contract
declares has a route or the suite fails, so a class added to the contract cannot
arrive here unnoticed.

The route then puts the event into the canonical form its class defines, so a
rule can be written once instead of once per way a collector spells things:
`SSH` and `ssh` are one service, `WEB-01.` and `web-01` are one host, and
`::ffff:10.0.0.5` and `10.0.0.5` are one address. It rewrites the event in
memory only — the store keeps what the agent sent, because the store is
evidence — and it never rewrites a field where the representation is the
meaning, such as an account name or the collected line itself. Every string the
contract carries has a recorded decision and a reason, and a string added to the
contract fails the suite until it has one. [ADR 5](docs/decisions/0005-the-canonical-form-is-for-analysis.md)
carries the reasoning. Detection arrives behind the same route.

`store-migrator` applies the store schema and exits. It is the only thing that
changes the shape of the store, and `event-writer` refuses to start against a
store that is behind the schema it ships.

`backbone-migrator` applies the topic topology and exits, on the same terms. It
is the only thing that creates or configures a topic, and both halves of the
data plane refuse to start when a topic they depend on is missing or reshaped.

`control-api` serves the protocol descriptor an agent needs before it can talk
to anything else. It exists mainly to prove that a second executable reuses the
platform foundation without copying it.

## What a detection rule is

`internal/detection` is the model and none of the runtime: a rule names the class
of event it reads, matches with an expression over fields of
`seagull.event.v1.Event`, and carries what an analyst is owed when it fires — a
severity, an ATT&CK technique, what a false positive looks like, and what to do
about it. Nothing evaluates a rule yet.

The vocabulary a rule matches on is derived from the contract rather than
written down, so `authentication.user.name` is a field because the contract says
so, `authentication.network.source.port` holds a number because the contract
says so, and `authentication.outcome` accepts `success` or `failure` because
those are the values the contract declares. A rule naming anything else is
refused where it is written, with the part of the rule that is wrong.
[ADR 6](docs/decisions/0006-a-rule-addresses-the-contract.md) records why there
is no dictionary between a rule and the contract, and what the model
deliberately cannot say yet.

## Getting started from a clean clone

```bash
make dev-pki            # mint a development CA, gateway and agent certificates
make up                 # build the images and start Redpanda + both services
make verify             # the full gate: lint, tests, race detector
```

`make up` writes nothing outside the repository and reads nothing that is not in
it. The development material lands in `.local/pki`, which is ignored by Git.

Send a batch through the running gateway:

```bash
go run ./tools/devprobe -endpoint https://127.0.0.1:8443
```

If a port is already taken on your machine, publish somewhere else:

```bash
SEAGULL_GATEWAY_PUBLISH=127.0.0.1:18443 \
SEAGULL_CONTROL_API_PUBLISH=127.0.0.1:18080 make up
```

Stop everything and drop its state:

```bash
make down
```

## Repository layout

```text
cmd/                    one directory per process
  ingest-gateway/       the only durable entry point for telemetry
  analysis-engine/      the backbone's analytical consumer
  event-writer/         the backbone's consumer half, writing to the store
  store-migrator/       applies the store schema, then exits
  backbone-migrator/    applies the topic topology, then exits
  control-api/          the control plane entry point

internal/
  event/                what a well formed event is
  detection/            what a detection rule is, and what makes one runnable
  agentidentity/        what a verified agent identity is
  protocol/             version negotiation between agent and platform
  ingest/               admission control and the ingest transport
  analysis/             what analysing an event off the backbone means
  eventstore/           what a stored event is, and what is refused
  broker/               the Redpanda adapter
  clickhouse/           the store adapter and its embedded schema
  devpki/               development certificate material
  platform/             infrastructure shared by every process
    config/             environment parsing, validation, secrets
    log/                structured logging
    metrics/            the process metric registry
    health/             liveness and readiness
    httpx/              HTTP server lifecycle and instrumentation
    tlsx/               TLS material with renewal
    ops/                the operational listener
    run/                component lifecycle and shutdown
    service/            the process skeleton every executable starts from

tests/
  fixtures/             event builders shared by the suites
  architecture/         the dependency rules, enforced
  e2e/                  the gateway over real mutual TLS
  integration/          the data plane against a live Redpanda and ClickHouse
  load/                 the gateway under load, against a live Redpanda

deploy/                 Dockerfile and Compose
tools/                  development programs, not shipped
```

Dependencies point one way: `cmd` → capability → domain, adapters plug in at the
edges, and `internal/platform` never learns about the product. `make test`
enforces this in `tests/architecture`, so a violation fails the build rather
than a review.

## Configuration

Every setting is an environment variable. An empty value counts as unset,
because Compose renders unset variables as empty strings. Any variable can be
read from a file instead by adding the `_FILE` suffix, which is how secrets
reach a container without going through the environment.

Startup reports every configuration problem at once and then exits:

```text
ingest-gateway: invalid configuration: SEAGULL_BACKBONE_BROKERS: is required
SEAGULL_GATEWAY_AGENT_CA: is required
SEAGULL_GATEWAY_TLS_CERT: is required
SEAGULL_GATEWAY_TLS_KEY: is required
```

### Shared by every process

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `SEAGULL_LOG_FORMAT` | `json` | `json` or `text` |
| `SEAGULL_OPS_ADDRESS` | `127.0.0.1:9100` | where `/healthz`, `/readyz` and `/metrics` listen |
| `SEAGULL_SHUTDOWN_TIMEOUT` | `20s` | how long a graceful stop may take |
| `SEAGULL_READINESS_CACHE` | `5s` | how long a readiness verdict is reused |
| `SEAGULL_READINESS_TIMEOUT` | `2s` | budget for a single readiness check |
| `SEAGULL_TENANT_ID` | `default` | tenant stamped on admitted events |

The operational listener binds to loopback unless a deployment says otherwise.
A container that needs to be scraped sets `SEAGULL_OPS_ADDRESS` explicitly, so
exposing metrics and readiness is always a visible decision.

### ingest-gateway

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_GATEWAY_ADDRESS` | `0.0.0.0:8443` | the mutual TLS listener agents connect to |
| `SEAGULL_GATEWAY_TLS_CERT` | required | server certificate |
| `SEAGULL_GATEWAY_TLS_KEY` | required | server private key |
| `SEAGULL_GATEWAY_AGENT_CA` | required | authority that agent certificates must chain to |
| `SEAGULL_GATEWAY_MAX_BODY` | `8MiB` | ceiling on a batch body, counted as it is read |
| `SEAGULL_GATEWAY_MAX_EVENTS_PER_BATCH` | `1000` | ceiling on events in one batch |
| `SEAGULL_GATEWAY_PUBLISH_TIMEOUT` | `10s` | budget for making a batch durable |
| `SEAGULL_GATEWAY_RATE_PER_SECOND` | `200` | per-agent batch budget, `0` disables it |
| `SEAGULL_GATEWAY_RATE_BURST` | `400` | per-agent burst |
| `SEAGULL_GATEWAY_RATE_TRACKED_AGENTS` | `10000` | how many agents the limiter remembers |
| `SEAGULL_GATEWAY_ID` | `ingest-gateway` | recorded on every admitted event |
| `SEAGULL_EVENT_MAX_CLOCK_SKEW` | `5m` | how far ahead of the platform clock an event may be |
| `SEAGULL_EVENT_MAX_AGE` | `168h` | how old an event may be and still be admitted |

The batch ceiling is measured, not chosen. No event in a batch is published until
every event in it has been decoded and validated, so a larger batch is a larger
body that must be fully materialised before one byte reaches the backbone. At a
thousand the gateway sustains 727k events/s with a p99 of 139ms; at ten thousand
it sustains 300k with a p99 of three seconds. `make test-load` is where those
numbers come from.

### The backbone, shared by both halves of the data plane and the migrator

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_BACKBONE_BROKERS` | required | comma separated broker addresses |
| `SEAGULL_BACKBONE_EVENTS_TOPIC` | `security.events.raw` | admitted telemetry |
| `SEAGULL_BACKBONE_EVENTS_PARTITIONS` | `12` | how far per-agent ordering spreads |
| `SEAGULL_BACKBONE_EVENTS_RETENTION` | `168h` | how far back a replay can reach |
| `SEAGULL_BACKBONE_QUARANTINE_TOPIC` | `security.events.quarantine` | refused records |
| `SEAGULL_BACKBONE_QUARANTINE_PARTITIONS` | `3` | |
| `SEAGULL_BACKBONE_QUARANTINE_RETENTION` | `720h` | |
| `SEAGULL_BACKBONE_REPLICAS` | `1` | replication factor of every topic |

Every process reads the same declaration: `backbone-migrator` applies it, and
the gateway and the writer verify it before they serve.

### analysis-engine

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_ANALYSIS_CONSUMER_GROUP` | `analysis-engine` | the consumer group that owns its offsets |
| `SEAGULL_ANALYSIS_BATCH_EVENTS` | `5000` | records per poll |
| `SEAGULL_ANALYSIS_FETCH_MAX_WAIT` | `1s` | how long a poll waits before returning short |
| `SEAGULL_ANALYSIS_START_TIMEOUT` | `30s` | budget for verifying the topology before serving |

### event-writer

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_WRITER_CONSUMER_GROUP` | `event-writer` | the consumer group that owns the offsets |
| `SEAGULL_WRITER_BATCH_EVENTS` | `5000` | records per poll, and per store batch |
| `SEAGULL_WRITER_FETCH_MAX_WAIT` | `1s` | how long a poll waits before returning short |
| `SEAGULL_WRITER_RETRY_DELAY` | `1s` | first delay before a batch is retried |
| `SEAGULL_WRITER_RETRY_DELAY_MAX` | `30s` | ceiling the delay backs off to |

### event-writer and store-migrator

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_EVENT_STORE_ADDRESS` | required | the store's native protocol address, `clickhouse:9000` |
| `SEAGULL_EVENT_STORE_DATABASE` | `seagull` | the database holding `security_events` |
| `SEAGULL_EVENT_STORE_USER` | `seagull` | |
| `SEAGULL_EVENT_STORE_PASSWORD` | empty | read from `..._FILE` in a deployment |
| `SEAGULL_EVENT_STORE_TIMEOUT` | `30s` | budget for one write attempt, and to dial |

The connection to the store carries no TLS, deliberately: the gateway already
reaches Redpanda in the clear on the same internal network, and securing one leg
of the data plane and not the other would describe a boundary that is not there.

### control-api

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_CONTROL_API_ADDRESS` | `127.0.0.1:8080` | the API listener |
| `SEAGULL_CONTROL_API_TLS_CERT` | empty | server certificate |
| `SEAGULL_CONTROL_API_TLS_KEY` | empty | server private key |
| `SEAGULL_CONTROL_API_MAX_BODY` | `1MiB` | ceiling on a request body |

Without TLS material the control API only starts on loopback. A listener that
reaches further and carries no certificate is refused at startup.

## The acknowledgement contract

An agent may drop its local copy of a batch only when the gateway answers `200`
with `accepted`, `durable` and a `received` count equal to what it sent. Every
other answer means the agent keeps the batch and retries:

| Status | Meaning for the agent |
|---|---|
| `200` | the backbone owns the batch; drop the local copy |
| `400` | the payload is not a valid batch; do not retry unchanged |
| `403` | the connection carries no usable agent identity |
| `413` | the body is above the gateway ceiling; send smaller batches |
| `415` | the batch was not sent as protobuf |
| `422` | an event failed admission; the answer names the index and the field |
| `426` | the protocol version is not supported by this gateway |
| `429` | the agent is above its budget; back off |
| `503` | the batch was not made durable; retry |

Delivery is at least once. Duplicate suppression belongs to the consumers,
keyed on `event_id`, which the producer derives deterministically. The gateway
holds no deduplication state, which is what keeps it stateless and horizontally
scalable.

## Event time

Three timestamps are distinct and never collapsed:

- `time.event_time` — when it happened on the endpoint, written by the producer.
- `time.observed_time` — when the collector saw it, written by the producer.
- `reception.ingest_time` — when the platform accepted it, written by the gateway.

The gateway replaces the whole `reception` message and the identity fields in
`origin`, so a producer cannot choose its own identity, tenant, or place in the
platform's timeline.

## The backbone topology

Two topics, declared once in `internal/broker` and applied by
`backbone-migrator`:

| Topic | Partitions | Retention | Why |
|---|---|---|---|
| `security.events.raw` | 12 | 7 days | admitted telemetry, keyed by agent |
| `security.events.quarantine` | 3 | 30 days | refused records, kept longer because they are the ones still waiting to be read |

**Partitions and replication are refused, never converged.** Records are keyed
by `agent_id`, so growing the partition count moves an agent to a different
partition and silently ends the per-agent ordering that stateful detection will
depend on. The migrator reports the divergence and stops; changing the shape of
a live topic stays an operator's decision.

**Retention, cleanup and compression do converge.** They describe how long the
backbone keeps what it already ordered, so a run brings them back to the
declaration and reports what it changed.

**Startup verifies rather than assumes.** Readiness reaches the brokers, not the
topics, so a gateway whose topic is missing starts, reports itself healthy, and
then fails every batch an agent sends. A topic with the wrong shape is worse:
one partition instead of twelve works perfectly and only collapses the per-agent
ordering. The gateway and the writer describe their topics first and refuse to
serve when one is missing or reshaped:

```bash
docker compose -f deploy/compose.yaml run --rm backbone-migrator
```

Retention drift is logged as `backbone_topology_drift` and does not stop a
process: refusing to admit telemetry over a setting the process cannot fix would
trade the stream for the window.

## The telemetry store

One table, `security_events`, holding one row per admitted event, projected from
the contract by `internal/eventstore`. A field exists there because the contract
carries it, and a test walks the protobuf descriptor to make sure the contract
cannot grow a field the store quietly stops keeping.

No column is `Nullable`: absence is the zero value, which is exactly what proto3
means by an unset field. Enums are stored under their own name with the
contract's prefix removed and lowercased, so a value added to the contract needs
no migration. A new event class does need one, which is the friction intended.

**Duplicates.** Delivery is at least once, so a crash between the write and the
commit replays a batch. The table is a `ReplacingMergeTree` ordered by
`(tenant_id, event_time, event_id)`, so the replay collapses back to one row —
but that happens **on merge**, not on insert. A query that must not see a
duplicate has to ask for it:

```sql
SELECT count() FROM security_events FINAL WHERE tenant_id = 'acme';
```

**Retention.** `TTL event_time + INTERVAL 365 DAY`. A security store without
retention fills disks; changing the window is a later migration.

**Schema changes** are versioned SQL embedded in the binary and applied by
`store-migrator`, never at process startup. `event-writer` verifies at startup
that every migration it ships is applied, and refuses to run otherwise:

```bash
docker compose -f deploy/compose.yaml run --rm store-migrator
```

**Scaling** is horizontal. One `event-writer` is a single sequential loop —
poll, write, commit — with no worker pool and no buffering, because at 5000-row
batches there is nothing for concurrency to win. More throughput means more
instances of the process, and the topic's partitions divide between them.

**Quarantine.** A refused record is published to `security.events.quarantine` as
the bytes that arrived, with `quarantine-reason`, `quarantine-detail`,
`source-partition` and `source-offset` as record headers. It is replayable by
construction, and wrapping an unparseable payload in a second schema — which
would itself have to parse — is avoided. Payloads are never logged: a refused
record can carry an attacker's input, and the position is enough to fetch it.

## Contracts

The messages exchanged with agents live in
[Seagull-contracts](https://github.com/dynasmon/Seagull-contracts) and are
consumed here as an ordinary module dependency. They are not defined in this
repository, because an agent has to be able to speak the contract without
depending on the platform.

```go
import eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
```

Changing a message means a release of that repository, where `buf breaking`
decides whether the change is allowed.

## Tests

```bash
make test              # unit, architecture and end-to-end suites
make test-race         # the same suites under the race detector
make test-integration  # the data plane against a live Redpanda and ClickHouse
make test-load         # the ingest load scenarios against a live Redpanda
make bench             # the hot path, one core, no infrastructure
```

The end-to-end suite starts a real mutual TLS listener with a certificate
authority minted in the test, so no fixture files are needed and nothing depends
on the machine it runs on. It also runs under a goroutine leak detector.

`make test-integration` starts the broker and the store through
`deploy/compose.test.yaml`, which is the only place either is reachable from the
host. In the ordinary stack both sit on an internal network with no published
port. The suite ends with the whole slice — admission, backbone, writer, store —
running against real infrastructure, which is what the rest of it is a
decomposition of.

The load suite drives the real gateway over real mutual TLS against a live
backbone through five scenarios — sustained ingest, concurrent batches at three
sizes, a slow backbone, an abusive agent, and a shutdown under load — and
reports throughput, percentiles and allocation per event. A run fails when the
gateway allocates more than 8 KB per admitted event, when a slow backbone
produces an acknowledgement the backbone never received, or when a shutdown
drops a batch it had already answered for.

## Further reading

- [Architecture decisions](docs/decisions) — why the foundation looks like this.
