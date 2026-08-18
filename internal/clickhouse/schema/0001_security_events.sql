-- One row per admitted event, projected from the contract by internal/eventstore.
-- Nothing is Nullable: absence is the zero value, as in proto3.
-- One column per line, name first: internal/clickhouse reads this file to check
-- the adapter inserts into exactly these columns, in this order.

CREATE TABLE IF NOT EXISTS security_events
(
    event_id              String,
    schema_version        UInt32,
    event_class           LowCardinality(String),
    event_time            DateTime64(3, 'UTC'),
    observed_time         DateTime64(3, 'UTC'),
    ingest_time           DateTime64(3, 'UTC'),

    tenant_id             LowCardinality(String),
    agent_id              LowCardinality(String),
    host_hostname         String,
    host_ip               String,
    host_os               LowCardinality(String),
    host_architecture     LowCardinality(String),

    collector             LowCardinality(String),
    source                String,
    sequence              UInt64,

    gateway               LowCardinality(String),
    batch_id              String,

    auth_activity         LowCardinality(String),
    auth_outcome          LowCardinality(String),
    auth_outcome_reason   LowCardinality(String),
    auth_method           LowCardinality(String),
    auth_user_name        String,
    auth_user_domain      String,
    auth_user_uid         String,
    auth_service_name     LowCardinality(String),
    auth_service_protocol LowCardinality(String),
    auth_source_ip        String,
    auth_source_port      UInt16,
    auth_destination_ip   String,
    auth_destination_port UInt16,
    auth_transport        LowCardinality(String),
    auth_raw_record       String
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, event_time, event_id)
TTL toDateTime(event_time) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192
