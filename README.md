# Seagull v2

A security event processing platform. Telemetry becomes durable on an event
backbone before anything else happens to it; the control plane is built around
that pipeline rather than the other way around.

This repository holds the foundation and the ingest half of the first vertical
slice. Normalization, detection, correlation and the control plane are not
implemented yet.

## What runs today

```text
Seagull Agent
      |  mutual TLS, protobuf
      v
cmd/ingest-gateway  ── admission control ──▶  Redpanda  security.events.raw
      |                                             (durable before the ack)
      v
cmd/control-api     ── protocol descriptor
```

`ingest-gateway` authenticates an agent by its client certificate, admits or
refuses the batch, publishes it to the backbone and answers only once the
backbone owns it. It holds no database, no cache and no analytics.

`control-api` serves the protocol descriptor an agent needs before it can talk
to anything else. It exists mainly to prove that a second executable reuses the
platform foundation without copying it.

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
  control-api/          the control plane entry point

internal/
  event/                what a well formed event is
  agentidentity/        what a verified agent identity is
  protocol/             version negotiation between agent and platform
  ingest/               admission control and the ingest transport
  broker/               the Redpanda adapter
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
  integration/          the backbone against a live Redpanda

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
| `SEAGULL_GATEWAY_MAX_EVENTS_PER_BATCH` | `10000` | ceiling on events in one batch |
| `SEAGULL_GATEWAY_PUBLISH_TIMEOUT` | `10s` | budget for making a batch durable |
| `SEAGULL_GATEWAY_RATE_PER_SECOND` | `200` | per-agent batch budget, `0` disables it |
| `SEAGULL_GATEWAY_RATE_BURST` | `400` | per-agent burst |
| `SEAGULL_GATEWAY_RATE_TRACKED_AGENTS` | `10000` | how many agents the limiter remembers |
| `SEAGULL_GATEWAY_ID` | `ingest-gateway` | recorded on every admitted event |
| `SEAGULL_EVENT_MAX_CLOCK_SKEW` | `5m` | how far ahead of the platform clock an event may be |
| `SEAGULL_EVENT_MAX_AGE` | `168h` | how old an event may be and still be admitted |
| `SEAGULL_BACKBONE_BROKERS` | required | comma separated broker addresses |
| `SEAGULL_BACKBONE_EVENTS_TOPIC` | `security.events.raw` | where admitted events are published |

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
make test-integration  # the backbone suite against a live Redpanda
```

The end-to-end suite starts a real mutual TLS listener with a certificate
authority minted in the test, so no fixture files are needed and nothing depends
on the machine it runs on. It also runs under a goroutine leak detector.

`make test-integration` starts the broker through `deploy/compose.test.yaml`,
which is the only place the backbone is reachable from the host. In the ordinary
stack it sits on an internal network with no published port.

## Further reading

- [Architecture decisions](docs/decisions) — why the foundation looks like this.
