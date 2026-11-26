-- The security audit trail, one row per entry of a chain: each tenant's events
-- are one chain and the events of no tenant are another, chained by
-- audit-writer alone in the order security.audit holds them
-- (internal/auditstore). One column per line, name first: internal/clickhouse
-- reads this file to check the adapter inserts into exactly these columns, in
-- this order.
--
-- A MergeTree and not a ReplacingMergeTree. Two rows at one sequence are
-- evidence that something wrote where the chain already stood, and a merge that
-- kept one of them would erase it; a credential that may only insert could then
-- replace an entry. A retried insert of the same block is one block
-- (non_replicated_deduplication_window), and a writer that lost its partition
-- writes rows identical to the ones the next writer makes, which a reader takes
-- as one entry.
--
-- No TTL and no PARTITION BY: an entry leaves only with every entry before it
-- on its chain, once a signed checkpoint has sealed them, and a chain's newest
-- entry never leaves, since it is where the next one is chained from. The
-- columns between the digest and the event are what a reader filters by; the
-- event is the seagull.audit.v1.Event exactly as it was published, which is
-- what the digest covers.

CREATE TABLE IF NOT EXISTS audit_entries
(
    chain         LowCardinality(String),
    sequence      UInt64,
    previous      FixedString(32),
    digest        FixedString(32),

    event_id      String,
    occurred_at   DateTime64(3, 'UTC'),
    action        LowCardinality(String),
    actor_subject String,
    target_id     String,

    log_partition Int32,
    log_offset    Int64,

    event         String,

    INDEX event_id_bloom event_id TYPE bloom_filter GRANULARITY 1
)
ENGINE = MergeTree
ORDER BY (chain, sequence)
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000
