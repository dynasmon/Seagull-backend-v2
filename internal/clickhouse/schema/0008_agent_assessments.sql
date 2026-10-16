-- Every assessment an agent made of its host, projected by
-- internal/assessmentstore and written by assessment-projector. Nothing is
-- Nullable: absence is the zero value, as in proto3. One column per line, name
-- first: internal/clickhouse reads this file to check the adapter inserts into
-- exactly these columns, in this order.
--
-- One row per assessment rather than one per agent, because an agent keeps an
-- assessment until the platform holds it so that what a posture was over time
-- can be read back. The newest one of an agent, by `assessed_at`, is its
-- posture. An assessment published twice — an answer the agent never received,
-- a replay — has the same key and merges into one row, versioned by the
-- platform's clock.
--
-- `assessment` is the seagull.assessment.v1.Assessment exactly as the gateway
-- published it, which is what a reader of one agent is handed; the columns
-- beside it are what an estate is asked about without decoding every one.

CREATE TABLE IF NOT EXISTS agent_assessments
(
    tenant_id       LowCardinality(String),
    agent_id        LowCardinality(String),
    assessment_id   String,
    ingest_time     DateTime64(3, 'UTC'),

    assessed_at     DateTime64(3, 'UTC'),
    policy_id       LowCardinality(String),
    policy_revision UInt64,

    checks          UInt32,
    passed          UInt32,
    failed          UInt32,
    errors          UInt32,
    unsupported     UInt32,
    not_applicable  UInt32,

    assessment      String
)
ENGINE = ReplacingMergeTree(ingest_time)
PARTITION BY toYYYYMM(assessed_at)
ORDER BY (tenant_id, agent_id, assessed_at, assessment_id)
TTL toDateTime(assessed_at) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192
