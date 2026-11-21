-- What the platform found about every agent from how it reports and presents
-- itself, one row per finding, projected by internal/agentfindingstore and
-- written by agent-finding-writer. Nothing is Nullable: absence is the zero
-- value, as in proto3, so a closed_at of zero is a finding still open. One column
-- per line, name first: internal/clickhouse reads this file to check the adapter
-- inserts into exactly these columns, in this order.
--
-- The version is decided_at, the platform's clock, because where a finding
-- stands is its newest decision. There is no PARTITION BY, for the reason
-- agent_status has none: every candidate is a time that moves with each decision,
-- and a partition would keep one row per finding per month that no merge
-- reconciles. An open finding is decided again every day it stays open, so the
-- TTL takes a finding a year after it was last decided and never one still open.
--
-- `finding` is the seagull.agent.v1.Finding exactly as it was published, which
-- is what a reader is handed; the columns beside it are what a reader filters,
-- orders and counts by without decoding every decision.

CREATE TABLE IF NOT EXISTS agent_findings
(
    tenant_id        LowCardinality(String),
    agent_id         LowCardinality(String),
    finding_id       String,

    kind             LowCardinality(String),
    state            LowCardinality(String),
    closure          LowCardinality(String),

    opened_at        DateTime64(3, 'UTC'),
    last_observed_at DateTime64(3, 'UTC'),
    observations     UInt64,
    closed_at        DateTime64(3, 'UTC'),
    decided_at       DateTime64(3, 'UTC'),

    finding          String
)
ENGINE = ReplacingMergeTree(decided_at)
ORDER BY (tenant_id, agent_id, finding_id)
TTL toDateTime(decided_at) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192
