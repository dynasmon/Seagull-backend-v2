# Seagull v2

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Backend](https://img.shields.io/badge/backend-Go%201.26-00ADD8.svg)](go.mod)
[![Backbone](https://img.shields.io/badge/backbone-Redpanda-E7407A.svg)](deploy/compose.yaml)
[![Store](https://img.shields.io/badge/store-ClickHouse-FFCC01.svg)](internal/clickhouse)
[![Contracts](https://img.shields.io/badge/contracts-Seagull--contracts-00A6A6.svg)](https://github.com/dynasmon/Seagull-contracts)

<!-- progress:start -->
## Backlog progress

**40% to go** · 60% built · updated on 2026-11-26

<img src="https://geps.dev/progress/60?label=40%25%20to%20go" width="100%" alt="60% built, 40% to go">

The bar counts the backend backlog's cards, a partial card as half. The cards left are the larger ones.

### What is left

- **Foundation** — Test harness and backtesting *(partial)*
- **Correctness** — Judge a Store Rebuild by What It Promises a Writer
- **Fleet visibility** — Detect Fleet Integrity Anomalies: Silence, Duplicate Identity and Tampering *(partial)*
- **Production** — Security Audit Log · Observability Contract per Process *(partial)* · Failure Recovery and Chaos Integration Suite *(partial)* · Backend Soak and Load Testing *(partial)* · Production Readiness Gate *(partial)* · Bootstrap Enrollment With Single-Use Tokens · Persistent Sessions and a Live Policy · Reference Deployment and Its Security Posture · Highly Available Stores · Backup, Restore and Disaster Recovery · Retention, Tiering and Data Subject Requests · Tenant Lifecycle and Quotas · Bound What an Update Package Costs the Control Plane
- **Linux SIEM** — Decide How a New Event Class Enters the Platform · Process Execution Events · Privilege and Account Management Events · File Integrity Events · Network Connection and DNS Events · Rule Language: Address Ranges, Distinct Counts and Reference Lists · Correlate Across Agents by Repartitioning on the Group Key · Backtest a Ruleset Against Recorded Telemetry · Detection Content Library and ATT&CK Coverage · Hunt Analytics and Investigative Indexes · Alert Tuning as a Published, Audited Document
- **SOC and operator identity** — Federated Operator Identity and the Browser-Facing API · Service Accounts and API Tokens for Integrations · Case Management · Notifications and Outbound Integrations · Saved and Scheduled Searches
- **Fleet management** — Signed Agent Policy Service *(partial)* · Agent Release Distribution and Staged Rollout *(partial)*
- **Response (XDR)** — Server-to-Agent Command Channel · Response Action Policy and Catalogue
- **Breadth** — Extend Vulnerability Coverage Where an Asset Can Be Placed · Ingest Third-Party Logs Through a Connector Gateway · Pull Connectors for Cloud and Identity Providers · Sequences Across Event Classes · Enrichment and Threat Intelligence · Behavioral Baselines (UEBA) · Rare Process per Host · Peer-Group Deviation
<!-- progress:end -->

Seagull v2 is the backend of an open security operations platform: small
processes around a durable event backbone (Redpanda), with ClickHouse for
telemetry and PostgreSQL for operator work. Telemetry is durable before it is
acknowledged, and everything downstream consumes that stream.

It re-architects [Seagull v1](https://github.com/dynasmon/Seagull) rather than
porting it: v1's detection content and lessons carry over, its structure does
not. The agent is released separately, and the messages the two exchange live in
[Seagull-contracts](https://github.com/dynasmon/Seagull-contracts).

## What the backend does

- **Ingestion**: mutual TLS, identity from the certificate, size and rate limits, and an answer only once the backbone holds the batch on two of three replicas. [ADR 1](docs/decisions/0001-durable-before-acknowledged.md), [37](docs/decisions/0037-a-record-is-bounded-by-what-its-topic-carries.md), [41](docs/decisions/0041-production-is-the-default-and-development-is-declared.md)
- **Detection**: typed rules over the event contract, with severity, ATT&CK and their own test cases. A rule may also count or order events inside a bounded event-time window. [ADR 6](docs/decisions/0006-a-rule-addresses-the-contract.md), [10](docs/decisions/0010-a-rule-carries-the-cases-it-was-written-for.md), [18](docs/decisions/0018-detection-state-is-a-bounded-window.md)–[20](docs/decisions/0020-a-sequence-is-decided-by-the-window-that-holds-it.md)
- **Sigma import**: supported Sigma rules become native rules, and what cannot be expressed is refused. It covers one event class so far. [ADR 22](docs/decisions/0022-sigma-is-translated-and-never-adopted.md)
- **Alerts and incidents**: a detection above a severity floor becomes an alert, and a correlation becomes an incident. Duplicates fold into one alert, and the detection itself is never changed. [ADR 16](docs/decisions/0016-an-alert-is-a-detection-somebody-owns.md), [17](docs/decisions/0017-noise-is-removed-from-the-alert-and-never-from-the-detection.md), [21](docs/decisions/0021-an-incident-is-a-correlation-somebody-owns.md)
- **Rulesets**: compiled, tested and published by the control plane, named by their content and activated separately, so a rollback is exact. [ADR 8](docs/decisions/0008-a-ruleset-is-named-by-what-is-in-it.md), [15](docs/decisions/0015-a-ruleset-is-published-to-a-log.md), [51](docs/decisions/0051-the-rules-an-installation-starts-from-are-its-first-publication.md)
- **Hunting and asset reads**: events, detections, inventory, findings and advisories, read only and within the tenants the policy grants. [ADR 13](docs/decisions/0013-a-query-is-a-scope-a-window-and-a-question.md), [47](docs/decisions/0047-the-query-plane-decides-by-the-policy-and-a-certificate-organisation-authorises-nothing.md), [59](docs/decisions/0059-the-read-plane-lists-what-an-asset-has-and-what-is-wrong-with-it.md)
- **Access control**: certificate login, short sessions, typed permissions on every route, deny by default, grants scoped to the platform or to named tenants. [ADR 14](docs/decisions/0014-a-token-says-who-and-the-policy-says-what.md), [50](docs/decisions/0050-a-grant-reaches-the-platform-or-the-tenants-it-names.md)
- **Backbone principals**: every process reaches Redpanda as itself, held to its own ACL grant. [ADR 60](docs/decisions/0060-a-component-reaches-the-backbone-as-itself-and-is-held-to-its-grant.md)
- **Agent registry**: register, activate, disable, revoke and decommission agents. The gateway enforces a revocation within 30 seconds without a database lookup and admits only the certificate in force. [ADR 24](docs/decisions/0024-an-agent-is-registered-by-the-control-plane-and-refused-by-the-gateway.md), [26](docs/decisions/0026-an-agent-sends-into-the-tenant-it-was-registered-in.md), [46](docs/decisions/0046-a-revocation-is-enforced-within-the-bound-a-gateway-confirms-its-roster-by.md), [58](docs/decisions/0058-a-listener-admits-an-agent-only-on-the-certificate-in-force.md)
- **Agent certificates**: the control plane signs and renews them. [ADR 25](docs/decisions/0025-the-platform-signs-the-identity-it-binds.md)
- **Agent policies and assessments**: policies signed off the platform change how agents run and which host checks they assess. [ADR 29](docs/decisions/0029-an-agent-policy-is-signed-off-the-platform.md), [33](docs/decisions/0033-a-posture-is-the-newest-assessment-of-checks-an-operator-signed.md)
- **Agent updates**: releases signed off the platform, after The Update Framework, rolled out to a tenant in waves that pause on reported failures. [ADR 31](docs/decisions/0031-an-agent-release-is-authorized-off-the-platform.md), [32](docs/decisions/0032-a-rollout-opens-a-release-wave-by-wave-and-pauses-on-what-agents-report.md)
- **Fleet health**: liveness from status reports, and findings for a silent agent, a copied installation, a shared identity and a replaced certificate in use. [ADR 30](docs/decisions/0030-an-agent-is-alive-while-its-reports-arrive.md), [56](docs/decisions/0056-a-finding-about-an-agent-is-a-record-of-its-own-judged-only-while-the-platform-listens.md), [57](docs/decisions/0057-a-place-is-a-run-and-a-renewal-is-refused-before-it-is-signed.md)
- **Inventory**: packages, services and accounts per asset. What is current is what the newest full scan named, and nothing is deleted. [ADR 27](docs/decisions/0027-inventory-is-a-record-kind-of-its-own.md), [43](docs/decisions/0043-a-record-keeps-apart-what-one-identity-would-fold.md)
- **Vulnerabilities**: advisories from OSV for Debian, Ubuntu, Alpine, Rocky Linux and AlmaLinux, matched against installed packages into one finding per package and CVE. Risk acceptances are kept apart. [ADR 28](docs/decisions/0028-vulnerability-intelligence-is-read-from-its-source.md), [49](docs/decisions/0049-a-finding-is-decided-by-one-reader-from-the-stores-their-owners-filled.md), [52](docs/decisions/0052-a-disposition-is-kept-beside-the-findings-it-covers.md)
- **Replay and failure**: a consumer commits only after its work is durable, a poison record goes to quarantine, and a replay gives the same rows and detections. [ADR 12](docs/decisions/0012-storage-is-owned-per-workload.md), [23](docs/decisions/0023-state-is-owned-by-the-partition-and-rebuilt-by-reading-it-back.md), [34](docs/decisions/0034-a-stored-event-is-named-by-the-agent-that-sent-it.md), [39](docs/decisions/0039-a-detection-is-named-by-the-agent-and-identifier-of-every-event-that-decided-it.md)

## Architecture

```text
Seagull Agent
      │  mutual TLS · protobuf
      ▼
ingest-gateway ──▶ Redpanda ──┬──▶ event-writer ───────────────────▶ ClickHouse ◀── query-api
                              │                                        ▲
                              └──▶ analysis-engine                     │
                                         │                             │
                                         ▼                             │
                                    detections ──┬──▶ detection-writer─┘
                                                 │
                                                 └──▶ alert-writer ──▶ PostgreSQL ◀── control-api
```

Every stream on the backbone, as [`internal/broker/grants.go`](internal/broker/grants.go) grants it:

| Stream | Written by | Read by |
|---|---|---|
| `security.events.raw` | ingest-gateway | event-writer, analysis-engine |
| `security.detections` | analysis-engine | detection-writer, alert-writer |
| `security.rulesets` | control-api | analysis-engine |
| `security.agents` | control-api | ingest-gateway, fleet-judge |
| `security.inventory.raw` | ingest-gateway | inventory-projector, vulnerability-matcher |
| `security.agents.status` | ingest-gateway | status-projector, fleet-judge |
| `security.assessments` | ingest-gateway | assessment-projector |
| `security.gateways`, `security.agents.refusals` | ingest-gateway | fleet-judge |
| `security.agents.findings` | fleet-judge, control-api | agent-finding-writer |
| `security.advisories` | advisory-importer | advisory-writer, vulnerability-matcher |
| `security.findings` | vulnerability-matcher | finding-writer |

The writers and projectors keep their streams in ClickHouse, except `alert-writer`,
which keeps alerts and incidents in PostgreSQL. What a ClickHouse writer cannot
store goes to a `.quarantine` topic of its own. `control-api` is the administrative
surface, `query-api` the read plane, `advisory-importer` the only process that
reaches the internet, and `backbone-migrator`, `store-migrator` and
`control-migrator` apply the schemas and exit. Every process is declared in
[`deploy/compose.yaml`](deploy/compose.yaml).

Dependencies point one way, `cmd` → capability → domain, and
[`tests/architecture`](tests/architecture) fails the build when they do not.

## Getting started

Requires Docker with the Compose plugin and Go 1.26.

```bash
make dev-pki    # development authorities and certificates, in .local/pki
make up         # build and start the backbone, the stores and every process
make verify     # lint, module graph, tests, race detector
make down       # stop everything and drop its state
```

Try it against the running stack:

```bash
go run ./tools/devprobe -endpoint https://127.0.0.1:8443                             # send a batch of events
go run ./tools/devprobe -hunt https://127.0.0.1:8444                                 # query them back
go run ./tools/devprobe -inventory                                                    # send an asset's inventory
go run ./tools/devprobe -agents https://127.0.0.1:8445 -renewals https://127.0.0.1:8446  # register, renew, revoke
go run ./tools/devprobe -dispositions https://127.0.0.1:8445                         # accept a risk and withdraw it
```

An agent on another machine needs the server certificates to name this one:

```bash
make dev-pki HOSTS=localhost,127.0.0.1,192.0.2.10
SEAGULL_GATEWAY_PUBLISH=0.0.0.0:8443 SEAGULL_CONTROL_API_RENEWAL_PUBLISH=0.0.0.0:8446 make up
```

Its `platform-ca.pem` is `.local/pki/agent-trust.pem`. Policies and updates are
signed off the platform with `tools/policysign` and `tools/updatesign`, and stay
off until `control-api` is given their public keys in `.local/signing`.
`make rotate-dev-pki` mints new authorities, so every agent has to enroll again.
A Redpanda volume from an older release is walked up with `make upgrade-backbone`.

## Agent compatibility

The platform serves the newest agent release and the one before it. Every answer
an agent reads is recorded in `tests/e2e/testdata/agent/protocol-1`, and a build
whose answers differ fails until `make record-agent-answers` records them again.
[ADR 48](docs/decisions/0048-every-answer-an-agent-reads-is-recorded-here-and-changes-only-by-a-version-decision.md)

## Configuration

Every setting is a typed environment variable, validated at startup. Adding
`_FILE` to its name reads it from a file, which is how secrets reach a container.
Production durability, TLS and authentication are the default, and a development
stack declares `SEAGULL_BACKBONE_DURABILITY=development`. Every setting is listed in
[`docs/configuration.md`](docs/configuration.md).

## Tests

```bash
make test              # unit, architecture and end-to-end suites
make test-race         # the same under the race detector
make test-integration  # against a live Redpanda and ClickHouse, including crash, replay and rebalance
make test-load         # ingest load scenarios
make test-alerts       # the operational alert rules
make bench             # the hot path
make vulncheck         # known vulnerabilities in linked packages
make gosec             # static security rules
make scan-images       # fixable high or critical vulnerabilities in built images
```

## Delivery

`main` takes a change only through a pull request every job passed. Images are
pinned by digest, actions by commit, and release tags are signed.
[ADR 44](docs/decisions/0044-main-takes-what-every-job-passed-and-a-release-line-moves-by-a-decision.md)

## Further reading

- [Architecture decisions](docs/decisions): why the platform looks like this, one record per decision.
- [Configuration reference](docs/configuration.md): every setting, the acknowledgement contract, the topics and the store.
- [Seagull-contracts](https://github.com/dynasmon/Seagull-contracts): the messages agents, the platform and the portal exchange.

## License

Seagull is licensed under the [GNU General Public License v3.0](LICENSE).
