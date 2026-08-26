-- One row per detection, projected from the contract by internal/detectionstore.
-- Nothing is Nullable: absence is the zero value, as in proto3.
-- One column per line, name first: internal/clickhouse reads this file to check
-- the adapter inserts into exactly these columns, in this order.
--
-- Detections and alerts are not the same table and never will be. A detection is
-- immutable and analytical; an alert is mutable, has an owner and a lifecycle,
-- and belongs in a relational store that does not exist yet. v1 kept both in one
-- `alerts` table and could not write an analytical result without touching a row
-- an operator owned.

CREATE TABLE IF NOT EXISTS security_detections
(
    detection_id           String,
    schema_version         UInt32,

    rule_id                LowCardinality(String),
    rule_revision          UInt32,
    rule_name              String,
    rule_source_catalogue  LowCardinality(String),
    rule_source_identifier String,
    ruleset_id             LowCardinality(String),

    severity               LowCardinality(String),
    technique_tactic       LowCardinality(String),
    technique_id           LowCardinality(String),
    technique_name         String,

    event_class            LowCardinality(String),
    tenant_id              LowCardinality(String),
    agent_id               LowCardinality(String),
    host_hostname          String,
    host_ip                String,
    host_os                LowCardinality(String),
    host_architecture      LowCardinality(String),

    source_event_ids       Array(String),
    event_time             DateTime64(3, 'UTC'),
    detected_time          DateTime64(3, 'UTC'),

    evidence_field         Array(String),
    evidence_operator      Array(String),
    evidence_negated       Array(Bool),
    evidence_held          Array(String),
    evidence_absent        Array(Bool)
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, event_time, detection_id)
TTL toDateTime(event_time) + INTERVAL 730 DAY DELETE
SETTINGS index_granularity = 8192
