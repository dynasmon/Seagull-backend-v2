-- security_events as it is kept from here on: a row says where the backbone held
-- the record it was written from, so a partition's events read back in position
-- order are the events, and the order, the analysis engine read. A row stored
-- before positions were kept holds -1 in both columns, which no record is at.
--
-- An event delivered twice is one row, and the engine decided it on its first
-- arrival, so the row kept is the one at the earliest position: the version is
-- the offset negated, and a row without a position, which arrived before any row
-- with one, precedes them all.
--
-- An engine cannot change in place. store-migrator creates this table, copies
-- every row of security_events into it and exchanges the two (rebuild.go); once
-- the migration is recorded, this name no longer exists.

CREATE TABLE IF NOT EXISTS security_events_rebuild
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
    log_partition         Int32 DEFAULT -1,
    log_offset            Int64 DEFAULT -1,

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
    auth_raw_record       String,

    arrival_precedence    Int64 MATERIALIZED -log_offset
)
ENGINE = ReplacingMergeTree(arrival_precedence)
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, event_time, agent_id, event_id)
TTL toDateTime(event_time) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192
