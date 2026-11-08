-- Which assets hold a package, under every name a distribution's advisories may
-- call it, projected by internal/inventorystore from the package rows it
-- stores. One column per line, name first: internal/clickhouse reads this file
-- to check the adapter inserts into exactly these columns, in this order.
--
-- asset_inventory is ordered to answer everything about one asset, and an
-- advisory asks the other way round. A PROJECTION would not answer it: a query
-- with FINAL does not read one, and a query without FINAL reads replaced rows.
-- The package is the name an advisory gives it, often not the one it was
-- installed under: the source a binary was built from for Debian, Ubuntu,
-- Alpine and Rocky Linux, the binary itself for AlmaLinux. A package is stored
-- before anyone knows the distribution of its asset, so it is listed under each.
--
-- This says where to look and never what is there. Whether an asset still has
-- the package, and at which version, is for asset_inventory to say against the
-- newest scan. A row that an upgrade or a removal left behind costs one more
-- lookup; a missing row would cost a finding, so the rows are written with the
-- package rows they name. The version, the absence of a partition and the TTL
-- are asset_inventory's, for its reasons.

CREATE TABLE IF NOT EXISTS asset_package_holders
(
    package   String,
    tenant_id LowCardinality(String),
    agent_id  LowCardinality(String),
    item_id   String,
    last_seen DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (package, tenant_id, agent_id, item_id)
TTL toDateTime(last_seen) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192
