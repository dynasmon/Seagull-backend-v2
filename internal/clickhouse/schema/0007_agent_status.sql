-- The newest status report of every agent, projected by internal/statusstore
-- and written by status-projector. Nothing is Nullable: absence is the zero
-- value, as in proto3. One column per line, name first: internal/clickhouse reads
-- this file to check the adapter inserts into exactly these columns, in this order.
--
-- One row per agent, and the version is ingest_time, which is the platform's
-- clock: how recently an agent was heard from is what liveness is judged on, so
-- it is never decided by a clock the agent controls. There is no PARTITION BY,
-- for the reason asset_inventory has none: every candidate is a time that moves
-- each time the agent reports, and a partition would keep one row per agent per
-- month that no merge reconciles.
--
-- `report` is the seagull.agent.v1.Status exactly as the gateway published it,
-- which is what a reader of one agent is handed; the columns beside it are what
-- a fleet is asked about without decoding every report.

CREATE TABLE IF NOT EXISTS agent_status
(
    tenant_id       LowCardinality(String),
    agent_id        LowCardinality(String),
    ingest_time     DateTime64(3, 'UTC'),

    reported_at     DateTime64(3, 'UTC'),
    installation_id String,
    sequence        UInt64,
    boot_id         String,
    interval_ms     UInt32,
    condition       LowCardinality(String),
    build_version   String,

    report          String
)
ENGINE = ReplacingMergeTree(ingest_time)
ORDER BY (tenant_id, agent_id)
TTL toDateTime(ingest_time) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192
