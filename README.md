# Seagull v2

A security event processing platform. Telemetry becomes durable on an event
backbone before anything else happens to it; the control plane is built around
that pipeline rather than the other way around.

This repository holds the foundation, the first vertical slice, the runtime the
analysis pipeline is built inside, and the plane a person reads the result from:
telemetry travels from an agent to a queryable store, every step of it is
durable, a second consumer reads the same stream and decides it against a
ruleset, what it finds crosses the backbone in a contract of its own and becomes
queryable too, and both stores can be asked questions within a scope, a window
and a budget. Correlation, alerts and the control plane are not implemented.

## What runs today

```text
Seagull Agent
      |  mutual TLS, protobuf
      v
cmd/ingest-gateway  ── admission control ──▶  Redpanda  security.events.raw
      |                                             (durable before the ack)
      |                                              |                    |
cmd/control-api     ── mutual TLS, sessions, RBAC     v                    v
                                        cmd/event-writer      cmd/analysis-engine
                                                 |                    |
                                                 ▼                    ▼
                                    ClickHouse  security_events   security.detections
                                                 |                    |
                                                 ▼                    ▼
                                       security.events.quarantine  cmd/detection-writer
                                                                      |
                                                                      ▼
                                                       ClickHouse  security_detections

cmd/query-api       ── mutual TLS, protobuf ──▶  both tables, read only
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
record into a `seagull.event.v1.Event`, routes it by the class it carries, puts
it into canonical form, decides it against the rules registered on that route,
publishes what it found to `security.detections` before advancing its group
position, refuses what it cannot read without returning an error — one unreadable
record must never hold a partition — and reports how long after admission each
event reached it.

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
carries the reasoning. Detection runs behind the same route.

`detection-writer` consumes `security.detections` and makes a detection
queryable. It is the same shape as the event writer — its own group, its own lag,
commit only after the batch is durable, quarantine what it cannot store — and it
never reads a rule, exactly as the analysis engine never reaches a store. The two
meet on the backbone and nowhere else.

`store-migrator` applies the store schema and exits. It is the only thing that
changes the shape of the store, and `event-writer` refuses to start against a
store that is behind the schema it ships.

`backbone-migrator` applies the topic topology and exits, on the same terms. It
is the only thing that creates or configures a topic, and both halves of the
data plane refuse to start when a topic they depend on is missing or reshaped.

`control-api` is the administrative surface. It terminates mutual TLS, exchanges
a verified certificate for a short-lived session bound to that certificate, and
decides every request against a policy of typed permissions it is pinned to. The
token says who; the policy says what, resolved fresh on each request, so a role
taken away lands at the next request rather than at the next expiry. Every route
declares what it requires and a route that declares nothing cannot be
registered. ADR 14.

`query-api` is the read plane. It holds the only read connection to the store,
consumes no topic and writes nothing, so an expensive question can reach neither
the pipeline that is still admitting telemetry nor the surface an operator acts
from. A caller is authenticated by certificate and the tenants they may read come
from it, so a query is answered within a scope the request cannot widen.

## What a detection rule is

`internal/detection` is the model and none of the runtime: a rule names the class
of event it reads, matches with an expression over fields of
`seagull.event.v1.Event`, and carries what an analyst is owed when it fires — a
severity, an ATT&CK technique, what a false positive looks like, and what to do
about it.

It also carries what somebody does with the rule rather than what the rule
decides: the tags it is filed under, the links that explain it, and where it came
from. `source` is empty for a rule this estate wrote and names the catalogue and
the identifier for one translated out of an upstream one, so a detection can be
traced past the rule to the thing the rule was made from.

The vocabulary a rule matches on is derived from the contract rather than
written down, so `authentication.user.name` is a field because the contract says
so, `authentication.network.source.port` holds a number because the contract
says so, and `authentication.outcome` accepts `success` or `failure` because
those are the values the contract declares. A rule naming anything else is
refused where it is written, with the part of the rule that is wrong.
[ADR 6](docs/decisions/0006-a-rule-addresses-the-contract.md) records why there
is no dictionary between a rule and the contract, and what the model
deliberately cannot say yet.

## How a rule is written and compiled

Rules are written in YAML files that `internal/rulefile` reads and the domain
never learns about, so Sigma and a control plane can feed the same model later
without becoming a second one:

```yaml
schema_version: 1
rules:
  - id: ssh.failed_password_from_outside
    revision: 1
    name: Failed SSH password from an external address
    description: A password authentication over SSH failed from outside the estate.
    class: authentication
    severity: medium
    status: active
    technique:
      tactic: credential_access
      id: T1110.001
      name: "Brute Force: Password Guessing"
    false_positives: An administrator mistyping a password from a home connection.
    response: Check for a pattern from the same address.
    tags: [ssh, credential_access]
    references:
      - https://attack.mitre.org/techniques/T1110/001/
    match:
      all:
        - field: authentication.outcome
          equals: failure
        - field: authentication.network.source.port
          at_least: 1024
        - not:
            field: authentication.network.source.ip
            starts_with: "10."
```

`detection.Compile` is the one door from that to something runnable: it
validates the rule, resolves every field to the contract's own descriptors,
compiles every literal into the type its field holds, and turns a long list into
a set — once, not per event. A number a field can never carry is refused, and so
is a rule that provably matches nothing or provably matches everything.

A refusal names the file, the line, the column, the rule and the part of it that
is wrong:

```text
rules/core/ssh.yml:11:14: rule "ssh.failed_password_from_outside": match.authentication.user.nam is not a field the contract declares
```

A ruleset is read whole or not at all, and every file that is wrong is reported
rather than only the first.
[ADR 7](docs/decisions/0007-a-rule-file-is-not-the-rule.md) records why the file
format is an adapter rather than the model.

## What a process is pinned to

`internal/ruleset` holds the compiled rules a process runs, as an immutable
snapshot named by a digest of everything its rules carry — so two processes
given the same rules report the same ruleset, and a detection will be able to
name exactly what decided it. Order does not change the name: the same rules
split across different files are the same ruleset.

A worker reads the current snapshot once and holds it for the whole of deciding
an event, so a reload arriving in the middle changes what the next event is read
against and never what this one is being read against. Reading takes no lock,
replacement is one atomic swap, and a reload that fails leaves the process
running exactly what it was running before. Where a ruleset comes from is a
`Source` an executable chooses; the registry itself reads no file.

```text
seagull_ruleset_info{ruleset="6a1c…"} 1
seagull_ruleset_rules{state="held"} 24
seagull_ruleset_rules{state="running"} 21
seagull_ruleset_reloads_total{outcome="applied"} 3
```

[ADR 8](docs/decisions/0008-a-ruleset-is-named-by-what-is-in-it.md) records why
the identity is a digest rather than a version, and what that buys replay and
backtesting.

## How an event is decided

Detection is a stage inside `analysis-engine`, not a process of its own: the
engine already consumes the backbone, and a second process would split the same
stream twice. A routed event is normalized, then decided against the rules the
current ruleset registers on that route.

Deciding is a pure function of a rule and an event. It reads nothing but the
message in front of it, keeps nothing between calls, writes nothing into the
event, does no I/O and cannot fail. A rule that does not match allocates nothing,
which is the answer most events give most rules. Saying what was decided is where
the stage can fail, and it fails as one batch rather than as one event: the whole
batch is published or the group position stays where it is.

A field the event does not carry answers no question. The contract does not
distinguish an unset field from one holding its zero value, so neither does a
rule: every comparison against an absent field is false, and `present` is the one
way to ask about the field itself. Negation then says the useful thing on its
own — a rule asking that a user is not `backup` also holds when the event
carries no user at all.

A match carries evidence: the fields the rule read and what the event held in
them, written the way a rule writes a literal. A disjunction is evidenced by the
branch that held; one that held nowhere keeps every branch, because under a
negation all of them failing is why the rule matched. Evidence is a set of what
the event said rather than a list of what the rule asked, so a rule refusing
three private prefixes on one field is evidenced once — what was asked in full
stays in the rule, and three copies of one answer would say nothing three times.

```text
authentication.outcome equals, and the event holds failure
authentication.service.protocol equals, and the event holds "ssh"
authentication.network.source.ip not starts_with, and the event holds "203.0.113.10"
```

A report names the rule, its revision, the severity, the ruleset, the event and
the fields the rule read — never what the event held, because a field value can
carry attacker input and evidence belongs in the detection record rather than in
a log line.

```text
seagull_detection_evaluations_total{route="authentication"} 41288
seagull_detection_matches_total{route="authentication",severity="medium"} 17
seagull_detection_seconds_bucket{route="authentication",le="0.00025"} 20644
```

Which rule fired is not a label: a ruleset is unbounded from the engine's point
of view, and what fired belongs in the detection record where it can be queried.
[ADR 9](docs/decisions/0009-an-absent-field-answers-no-question.md) records what
an absent field means and what a match owes an analyst.

## What a detection is

A `seagull.detection.v1.Detection` is what was found: the rule that decided it
at the revision it was decided at, the ruleset that held that rule, the agent
and tenant it is about, the events it was decided from, and the evidence. It
carries no status, no assignee and no disposition — those belong to an alert,
which has a lifecycle and an owner and is a later card. v1 kept all of it in one
`alerts` table and could not write an analytical result without touching a row an
operator owned.

It names the rule rather than repeating it. The ruleset is named by its own
content, so the rule's description, its false-positive guidance and its response
are recoverable from the set instead of copied into every detection the set
makes.

A detection is named by what decided it — the rule, the revision, and the events,
sorted and length prefixed — and by nothing else. Deciding the same events
against the same rule again produces the same name, which is what makes the
output stage safe to retry: a batch published twice is rewritten downstream
rather than counted twice. The ruleset is not part of the name, or an unrelated
rule arriving would rename every detection the others made; it travels beside the
name instead, so two detections that share one and disagree about the set they
came from is a visible state.

The engine publishes to `security.detections`, keyed by the agent the detection
is about, and commits its group position only once the backbone has taken the
batch — the same order the writer keeps against ClickHouse, retried with a
widening delay until it succeeds or the process stops. Nothing is dropped to make
progress, so a backbone that will not take a detection becomes visible consumer
lag rather than a finding nobody was told about.

```text
seagull_detection_published_total 173
seagull_detection_batches_total{outcome="published"} 41
seagull_detection_batches_total{outcome="retried"} 2
```

Against `matches_total`, `published_total` is the number that says whether what
the engine decided actually left the process. What materialises a detection is a
consumer of its own and knows nothing about the rules —
[ADR 11](docs/decisions/0011-a-detection-is-not-an-alert.md) records why a
detection, an alert and an event stay three different things.

## Where a detection is kept

`detection-writer` consumes `security.detections` into ClickHouse
`security_detections`, one row per detection, with the evidence stored as five
parallel arrays rather than as a document: what a rule read is a contract field
path and what the event held is a value, and both are worth filtering on. v1 kept
the equivalent in a JSON column and nothing could query it.

```sql
SELECT rule_id, severity, count()
FROM security_detections FINAL
WHERE tenant_id = 'default' AND event_time > now() - INTERVAL 1 DAY
GROUP BY rule_id, severity;

SELECT detection_id, evidence_field, evidence_held
FROM security_detections FINAL
WHERE has(evidence_field, 'authentication.network.source.ip');
```

The table is a `ReplacingMergeTree` ordered by `(tenant_id, event_time,
detection_id)` and partitioned by month, on the same timeline and the same
partitioning as the events it was made from. The sort key ends in the name the
engine gave the detection, so a replayed batch replaces rather than accumulates;
`FINAL` is required of a query that must not see a replayed row, which is the
same at-least-once story the event store tells rather than a claim of
exactly-once.

**Detections are kept for 730 days and telemetry for 365**, which is the right
way round: the finding is what an analyst returns to, the raw log is bulk, and a
detection carries its own evidence, so it stays readable after the events behind
it expire.

**There is no alerts table, and there will not be one here.** An alert is mutable,
owned by a person, and has a state machine with an actor on every transition —
a relational workload, and the opposite of an analytical one. It is not built
yet because nothing produces one.
[ADR 12](docs/decisions/0012-storage-is-owned-per-workload.md) records what each
class of data needs, which classes have an owner today, and which are left as a
question because they have no producer.

## How what was stored is read back

`query-api` answers questions about both tables. A query is three things, and
only the last of them comes from the caller:

```text
scope    which tenants may be read      from the caller's certificate
window   which stretch of time          required, half open, bounded
question which records within it        the caller's, held to the contract
```

A question is written in the vocabulary of the contract, never of the store —
`authentication.user.name`, not `auth_user_name` — and the field, the operator
and every literal are checked against what the contract says the field carries
before the store is asked anything:

```protobuf
Query {
  range: { start: 2026-08-26T00:00:00Z, end: 2026-08-27T00:00:00Z }
  where: all {
    { field: "authentication.outcome",         operator: EQUALS,   values: ["failure"] }
    { field: "authentication.service.name",    operator: EQUALS,   values: ["sshd"] }
    { field: "authentication.network.source.ip", operator: STARTS_WITH, values: ["203.0.113."] }
  }
  limit: 100
}
```

`POST /v1/hunt/events` answers with `seagull.event.v1.Event` records and
`POST /v1/hunt/detections` with `seagull.detection.v1.Detection` records — the
messages that crossed the backbone, rebuilt from the projection, so a reader
never learns a second vocabulary. Records come back newest first.

The pivot an investigation is built out of works because a detection names the
events it was decided from and the store keeps that as a column:

```text
source_event_ids  equals  <event_id>     the detections made from this event
evidence.field    equals  <field path>   the detections a rule read this field for
```

**The scope is not a filter.** A query cannot be compiled without one, an empty
one reads nothing rather than everything, and the tenant condition is the first
thing in every statement the adapter builds. Today it comes from the caller's
certificate — the common name says who is asking, the organisation says which
tenants they may read — so the listener has no plaintext mode and no mode without
a client certificate authority.

**A page is resumed by a key, not by an offset**, and the cursor carries a
signature of the query that issued it, so page two of one question cannot be
spent on another with a wider scope or different filters. A page that carried
anything is followed by a cursor; only an empty page says the range is
exhausted, because a store answers within a budget and can return fewer records
than it holds.

Every question is bounded: 32 predicates, 8 levels of nesting, 256 literals to a
predicate and 512 bytes to a literal are structural, and the widest window, the
page size, the read budget and how much of the store one read may examine are
configured. There is no regular expression and no wildcard, for the same reason
the rule language has none: a pattern hands the caller control of how much of the
store a question reads. [ADR 13](docs/decisions/0013-a-query-is-a-scope-a-window-and-a-question.md)
carries the reasoning, including why there is no parser yet.

## How a rule is held to what it was written for

A rule carries the cases it was written to satisfy, in the same file and in the
same vocabulary it matches on. A case is an event and what the rule should say
about it:

```yaml
    tests:
      - name: a failed password from an address outside the estate
        expect: match
        severity: medium
        evidence: [authentication.outcome, authentication.network.source.ip]
        event:
          authentication.outcome: failure
          authentication.network.source.ip: 203.0.113.10

      - name: the same failure from inside the estate
        description: The false positive the rule is written to avoid.
        expect: no_match
        event:
          authentication.outcome: failure
          authentication.network.source.ip: 10.0.0.5
```

A field the case does not name is a field the event does not carry, which is how
a case says that something is absent. `severity` and `evidence` are asked only
when they are written, and a case documenting a false positive is one that
expects no match, named after the false positive it documents.

`rulefile.Check` runs every case under a tree and reads nothing outside it — no
broker, no store, no container — so the same answer comes back in a test, in a
pipeline and in a control plane. Checking a case calls the same `Decide` the
engine calls, so a case cannot pass against an evaluator that does not ship.

```text
deploy/rules/authentication.yml: rule "ssh.failed_password_from_outside": case "a failure from inside the estate": the rule matched, on authentication.network.source.ip, authentication.outcome
```

A rule with no cases is reported rather than refused: whether to ship one is a
decision, and it is made where the ruleset is chosen. `cmd/analysis-engine` makes
it, and the answer is that every rule this repository ships carries its cases and
`make test` runs them.
[ADR 10](docs/decisions/0010-a-rule-carries-the-cases-it-was-written-for.md)
records why a case is beside the rule rather than in it.

## Getting started from a clean clone

```bash
make dev-pki            # mint a development CA, server, agent and caller certificates
make up                 # build the images and start Redpanda + both services
make verify             # the full gate: lint, tests, race detector
```

`make up` writes nothing outside the repository and reads nothing that is not in
it. The development material lands in `.local/pki`, which is ignored by Git.

Send a batch through the running gateway, and ask the query plane what became of
it:

```bash
go run ./tools/devprobe -endpoint https://127.0.0.1:8443
go run ./tools/devprobe -hunt https://127.0.0.1:8444
```

The caller certificate `make dev-pki` mints is authorised for the `default`
tenant, which is the one the local gateway stamps on everything it admits.

If a port is already taken on your machine, publish somewhere else:

```bash
SEAGULL_GATEWAY_PUBLISH=127.0.0.1:18443 \
SEAGULL_CONTROL_API_PUBLISH=127.0.0.1:18080 \
SEAGULL_QUERY_API_PUBLISH=127.0.0.1:18444 make up
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
  detection-writer/     what makes a detection queryable
  event-writer/         the backbone's consumer half, writing to the store
  store-migrator/       applies the store schema, then exits
  backbone-migrator/    applies the topic topology, then exits
  control-api/          the control plane entry point
  query-api/            the read plane, and the only reader of the store

internal/
  event/                what a well formed event is
  detection/            what a detection rule is, what compiles one, what checks one, what a detection is
  agentidentity/        what a verified agent identity is
  protocol/             version negotiation between agent and platform
  ingest/               admission control and the ingest transport
  analysis/             what analysing an event off the backbone means
  eventstore/           what a stored event is, and what is refused
  detectionstore/       what a stored detection is, and what is refused
  hunt/                 what a query is, who may ask it, and the transport it arrives on
  rulefile/             the rule file format, with the cases written beside a rule
  ruleset/              the compiled rules a process is pinned to
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
  e2e/                  the gateway and the query plane over real mutual TLS
  integration/          the data plane against a live Redpanda and ClickHouse
  load/                 the gateway under load, against a live Redpanda

deploy/                 Dockerfile, Compose, and the ruleset the local stack runs
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
| `SEAGULL_BACKBONE_DETECTIONS_TOPIC` | `security.detections` | what the rules decided |
| `SEAGULL_BACKBONE_DETECTIONS_QUARANTINE_TOPIC` | `security.detections.quarantine` | records the detection writer refused |
| `SEAGULL_BACKBONE_QUARANTINE_PARTITIONS` | `3` | |
| `SEAGULL_BACKBONE_QUARANTINE_RETENTION` | `720h` | |
| `SEAGULL_BACKBONE_REPLICAS` | `1` | replication factor of every topic |

Every process reads the same declaration: `backbone-migrator` applies it, and
the gateway and the writer verify it before they serve.

### analysis-engine

| Variable | Default | Meaning |
|---|---|---|
| `SEAGULL_ANALYSIS_CONSUMER_GROUP` | `analysis-engine` | the consumer group that owns its offsets |
| `SEAGULL_DETECTION_RULES` | `/etc/seagull/rules` | the rule tree the process is pinned to; it does not start without one |
| `SEAGULL_ANALYSIS_BATCH_EVENTS` | `5000` | records per poll |
| `SEAGULL_ANALYSIS_FETCH_MAX_WAIT` | `1s` | how long a poll waits before returning short |
| `SEAGULL_ANALYSIS_START_TIMEOUT` | `30s` | budget for verifying the topology before serving |
| `SEAGULL_DETECTION_PUBLISH_TIMEOUT` | `30s` | budget for making one batch of detections durable |
| `SEAGULL_DETECTION_RETRY_DELAY` | `1s` | first wait after the backbone refuses a batch of detections |
| `SEAGULL_DETECTION_RETRY_DELAY_MAX` | `30s` | ceiling that wait doubles towards |

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

The control plane authenticates a caller by certificate, so it has no plaintext
mode and no mode without a caller authority: without one there is nobody to be
authorised as. An unset session key is drawn at random, which means sessions stop
being spendable when the process stops.

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

Two topics, declared once in `internal/broker` and applied by
`backbone-migrator`:

| Topic | Partitions | Retention | Why |
|---|---|---|---|
| `security.events.raw` | 12 | 7 days | admitted telemetry, keyed by agent |
| `security.events.quarantine` | 3 | 30 days | refused records, kept longer because they are the ones still waiting to be read |
| `security.detections` | 6 | 30 days | what the rules decided, keyed by the agent it is about; narrower than the stream it is made from and kept as long as a refused record, for the same reason |
| `security.detections.quarantine` | 3 | 30 days | records the detection writer could not store; one quarantine per stream, because a refused record's partition and offset only mean something alongside the topic they came from |

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

`v0.3.0` carries `seagull.event.v1`, `seagull.ingest.v1`, `seagull.platform.v1`,
`seagull.detection.v1` and `seagull.hunt.v1`. A page of a hunt is made of the
same records the pipeline published, so asking a question and consuming the
stream speak one language.

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

The end-to-end suite starts real mutual TLS listeners with a certificate
authority minted in the test, so no fixture files are needed and nothing depends
on the machine it runs on. It also runs under a goroutine leak detector. It
covers the gateway and the query plane, where it proves that a caller with no
certificate is refused by the handshake and a caller authorised for nothing never
reaches the store.

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
