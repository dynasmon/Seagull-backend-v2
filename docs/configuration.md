# Configuration and operational reference

Every setting each process reads, the acknowledgement contract an agent depends
on, the topic topology, and the shape of the telemetry store. The reasoning
behind these choices lives in [the decision records](decisions); this file is
what to reach for when running the platform.

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
| `SEAGULL_BACKBONE_DETECTIONS_TOPIC` | `security.detections` | what the rules decided |
| `SEAGULL_BACKBONE_DETECTIONS_QUARANTINE_TOPIC` | `security.detections.quarantine` | records the detection writer refused |
| `SEAGULL_BACKBONE_RULESETS_TOPIC` | `security.rulesets` | published rulesets and the pointer at the one to run |
| `SEAGULL_BACKBONE_QUARANTINE_PARTITIONS` | `3` | |
| `SEAGULL_BACKBONE_QUARANTINE_RETENTION` | `720h` | |
| `SEAGULL_BACKBONE_REPLICAS` | `1` | replication factor of every topic |

Every process reads the same declaration: `backbone-migrator` applies it, and
the gateway and the writer verify it before they serve.

### analysis-engine

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_ANALYSIS_CONSUMER_GROUP` | `analysis-engine` | the consumer group that owns its offsets |
| `SEAGULL_DETECTION_RULES` | `/etc/seagull/rules` | the rule tree it starts on and falls back to; it does not start without one |
| `SEAGULL_ANALYSIS_RULESET_RECORDS` | `256` | ruleset records read per fetch |
| `SEAGULL_ANALYSIS_BATCH_EVENTS` | `5000` | records per poll |
| `SEAGULL_ANALYSIS_FETCH_MAX_WAIT` | `1s` | how long a poll waits before returning short |
| `SEAGULL_ANALYSIS_START_TIMEOUT` | `30s` | budget for verifying the topology before serving |
| `SEAGULL_DETECTION_PUBLISH_TIMEOUT` | `30s` | budget for making one batch of detections durable |
| `SEAGULL_DETECTION_RETRY_DELAY` | `1s` | first wait after the backbone refuses a batch of detections |
| `SEAGULL_DETECTION_RETRY_DELAY_MAX` | `30s` | ceiling that wait doubles towards |

The rule tree is the bootstrap, not the source of truth. The engine runs it
until `security.rulesets` names a published ruleset to run, and from then on the
log wins — which is what lets an engine keep detecting when no control plane is
reachable. ADR 15.

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

### detection-writer

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_DETECTION_WRITER_CONSUMER_GROUP` | `detection-writer` | the consumer group that owns the offsets |
| `SEAGULL_DETECTION_WRITER_BATCH_DETECTIONS` | `500` | records per poll, and per store batch |
| `SEAGULL_DETECTION_WRITER_FETCH_MAX_WAIT` | `1s` | how long a poll waits before returning short |
| `SEAGULL_DETECTION_WRITER_RETRY_DELAY` | `1s` | first delay before a batch is retried |
| `SEAGULL_DETECTION_WRITER_RETRY_DELAY_MAX` | `30s` | ceiling the delay backs off to |
| `SEAGULL_DETECTION_STORE_ADDRESS` | required | the store's native protocol address, `clickhouse:9000` |
| `SEAGULL_DETECTION_STORE_DATABASE` | `seagull` | the database holding `security_detections` |
| `SEAGULL_DETECTION_STORE_USER` | `seagull` | |
| `SEAGULL_DETECTION_STORE_PASSWORD` | empty | read from `..._FILE` in a deployment |
| `SEAGULL_DETECTION_STORE_TIMEOUT` | `30s` | budget for one write attempt, and to dial |

A batch is smaller than the event writer's because detections are rarer than the
telemetry they are made from, and waiting to fill five thousand of them would
keep the first one out of the store for longer than anyone would accept. The
store settings are the writer's own and point at the same server by default: two
processes choosing the same adapter is not the same as sharing one.

### alert-writer

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_ALERT_WRITER_CONSUMER_GROUP` | `alert-writer` | the consumer group that owns the offsets |
| `SEAGULL_ALERT_WRITER_BATCH_DETECTIONS` | `500` | records per poll, and per store batch |
| `SEAGULL_ALERT_WRITER_FETCH_MAX_WAIT` | `1s` | how long a poll waits before returning short |
| `SEAGULL_ALERT_WRITER_RETRY_DELAY` | `1s` | first delay before a batch is retried |
| `SEAGULL_ALERT_WRITER_RETRY_DELAY_MAX` | `30s` | ceiling the delay backs off to |
| `SEAGULL_ALERT_SEVERITY_FLOOR` | `medium` | how much a detection has to matter before it becomes somebody's work |
| `SEAGULL_ALERTING_DOCUMENT` | empty | how alerts fold and which never become work; the built-in fold is used when unset |

It reads `security.detections` in a group of its own, beside `detection-writer`
and never through it: a relational store nobody can reach stops alerts being
opened and does not stop detections being stored. A detection below the floor is
still stored, still queryable and still part of a hunt; it just does not become
work. It quarantines nothing — `detection-writer` already writes exactly the
records this cannot use to the detection quarantine, verbatim — and instead
steps over them, counted by reason in `alertstore_skipped_total`.

The alerting document says what an alert is keyed by, how long one absorbs what
shares its key, how long a closed one silences what follows it, and which
detections never become work at all. Without one the built-in fold applies:
`[rule, agent]` over fifteen minutes, and no cooldown, because a cooldown is the
only one of the three that can keep an operator from hearing about activity they
have not decided about.

```yaml
schema_version: 1

defaults:
  key: [rule, agent]     # a key must always name the rule
  window: 15m            # how long an open alert absorbs what shares its key
  cooldown: 0s           # how long a closed one silences what follows it

rules:
  - id: ssh.failed_password_from_outside
    key: [rule, agent, "evidence:authentication.source.ip"]
    window: 1h
    cooldown: 30m

suppressions:
  - rule: ssh.failed_password_from_outside
    when:
      agent: [scanner-01]
    reason: our own credentialed scanner   # required
    until: 2026-12-31T00:00:00Z            # optional, and worth writing
```

A key is a list of parts: `rule`, `agent`, `class`, `severity`, or
`evidence:<contract field path>`. The tenant is always in the key and is never
written. The same vocabulary is the suppression selector. Every window is
measured in **event time**, so replaying a batch decides what it decided the
first time. `alertstore_alerts_total` counts what became of every detection —
`raised`, `folded`, `repeated`, `cooled_down` — and `alertstore_suppressed_total`
is labelled by rule and by the reason written down. See
[ADR 17](decisions/0017-noise-is-removed-from-the-alert-and-never-from-the-detection.md).

### alert-writer, control-api and alert-migrator

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_ALERT_STORE_ADDRESS` | required | PostgreSQL address, `postgres:5432` |
| `SEAGULL_ALERT_STORE_DATABASE` | `seagull` | the database holding `alerts` and `alert_transitions` |
| `SEAGULL_ALERT_STORE_USER` | `seagull` | |
| `SEAGULL_ALERT_STORE_PASSWORD` | empty | read from `..._FILE` in a deployment |
| `SEAGULL_ALERT_STORE_SSLMODE` | `prefer` | `disable` only on a network you already trust |
| `SEAGULL_ALERT_STORE_MAX_CONNECTIONS` | `8` | connections one process will hold |
| `SEAGULL_ALERT_STORE_TIMEOUT` | `30s` | budget for one statement |
| `SEAGULL_ALERT_STORE_CONNECT_TIMEOUT` | `10s` | budget to dial |

`alert-migrator` applies the schema and exits, as `store-migrator` does for
ClickHouse. Both processes that read the store verify the schema before they
serve and refuse to run against one behind what they ship. The writer only ever
inserts and the control plane only ever updates, which is what keeps a replayed
detection away from somebody's triage.

### control-api

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_CONTROL_API_ADDRESS` | `127.0.0.1:8445` | the API listener |
| `SEAGULL_CONTROL_API_TLS_CERT` | required | server certificate |
| `SEAGULL_CONTROL_API_TLS_KEY` | required | server private key |
| `SEAGULL_CONTROL_API_CALLER_CA` | required | authority that issues caller certificates |
| `SEAGULL_CONTROL_API_POLICY` | required | the policy document to pin to |
| `SEAGULL_CONTROL_API_SESSION_KEY` | empty | key sessions are signed with; drawn at random when unset |
| `SEAGULL_CONTROL_API_SESSION_LIFETIME` | `15m` | how long a session lasts |
| `SEAGULL_CONTROL_API_SESSIONS_PER_CALLER` | `8` | sessions one subject may hold at once |
| `SEAGULL_CONTROL_API_SESSIONS_MAX` | `4096` | sessions the process will hold |
| `SEAGULL_CONTROL_API_RATE_PER_SECOND` | `20` | per-caller request budget |
| `SEAGULL_CONTROL_API_RATE_BURST` | `40` | burst above that budget |
| `SEAGULL_CONTROL_API_START_TIMEOUT` | `30s` | how long it will spend reading the ruleset log before it gives up |
| `SEAGULL_CONTROL_API_RULESET_RECORDS` | `256` | ruleset records read per fetch |

The control plane authenticates a caller by certificate, so it has no plaintext
mode and no mode without a caller authority: without one there is nobody to be
authorised as. An unset session key is drawn at random, which means sessions stop
being spendable when the process stops.

It also reads `SEAGULL_BACKBONE_BROKERS` and the ruleset topic, and reads that
topic whole before it serves: a control plane that had seen half the log would
report an estate nobody has. It holds the only mutating connection to the alert
store and takes the `SEAGULL_ALERT_STORE_*` settings above.

### query-api

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_QUERY_API_ADDRESS` | `127.0.0.1:8444` | the query listener |
| `SEAGULL_QUERY_API_TLS_CERT` | required | server certificate |
| `SEAGULL_QUERY_API_TLS_KEY` | required | server private key |
| `SEAGULL_QUERY_API_CALLER_CA` | required | the authority that signs a caller's certificate |
| `SEAGULL_QUERY_API_WINDOW` | `720h` | the widest stretch of time a query may ask about |
| `SEAGULL_QUERY_API_PAGE` | `50` | records in a page when the caller asks for no limit |
| `SEAGULL_QUERY_API_PAGE_MAX` | `500` | ceiling on the page a caller may ask for |
| `SEAGULL_QUERY_API_READ_BUDGET` | `15s` | how long one read may run in the store |
| `SEAGULL_QUERY_API_MAX_ROWS_READ` | `50000000` | how much of the store one read may examine |
| `SEAGULL_QUERY_API_CURSOR_KEY` | generated | signs a page token; set it when more than one replica serves one address |
| `SEAGULL_QUERY_API_MAX_BODY` | `256KiB` | ceiling on a query body |
| `SEAGULL_QUERY_STORE_ADDRESS` | required | ClickHouse address, read only |

There is no plaintext mode and no mode without a caller authority: the scope a
query is answered within comes from the caller's certificate, so without one
there is nobody to be authorised as. The write timeout has to outlast the read
budget or a query is cut off after the store has already paid for it, and the
process refuses to start when it does not.

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

Five topics, declared once in `internal/broker` and applied by
`backbone-migrator`:

| Topic | Partitions | Retention | Why |
|---|---|---|---|
| `security.events.raw` | 12 | 7 days | admitted telemetry, keyed by agent |
| `security.events.quarantine` | 3 | 30 days | refused records, kept longer because they are the ones still waiting to be read |
| `security.detections` | 6 | 30 days | what the rules decided, keyed by the agent it is about; narrower than the stream it is made from and kept as long as a refused record, for the same reason |
| `security.detections.quarantine` | 3 | 30 days | records the detection writer could not store; one quarantine per stream, because a refused record's partition and offset only mean something alongside the topic they came from |
| `security.rulesets` | 1 | compacted, kept | every published ruleset under its own content id, plus one `active` key naming the one to run; one partition because a version and the record activating it are only meaningful in the order they were written |

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
