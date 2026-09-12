-- One row per thing an asset currently has, projected from the contract by
-- internal/inventorystore. Nothing is Nullable: absence is the zero value, as in
-- proto3. One column per line, name first: internal/clickhouse reads this file to
-- check the adapter inserts into exactly these columns, in this order.
--
-- There is no PARTITION BY. ReplacingMergeTree collapses rows of one key only
-- within a partition, and every candidate to partition by here is a time that
-- moves as the item is observed again, so partitioning would leave one installed
-- package as a row per month that no merge ever reconciles.
--
-- The version is last_seen, which is the collector's own clock: a record that
-- reaches the store late, out of the order it was written in, loses to the newer
-- one it arrives behind rather than overwriting it.
--
-- Whether an item is still installed is not a column. The current items of one
-- kind on one asset are those whose last_seen is at or after the scanned_at that
-- asset_inventory_scans holds for it, so an item a full scan stopped naming
-- falls out of the answer without a delete, a tombstone or a second write.

CREATE TABLE IF NOT EXISTS asset_inventory
(
    tenant_id                   LowCardinality(String),
    agent_id                    LowCardinality(String),
    kind                        LowCardinality(String),
    item_id                     String,

    last_seen                   DateTime64(3, 'UTC'),
    mode                        LowCardinality(String),
    record_id                   String,
    schema_version              UInt32,

    host_hostname               String,
    host_ip                     String,
    host_os                     LowCardinality(String),
    host_architecture           LowCardinality(String),

    collector                   LowCardinality(String),
    source                      String,
    sequence                    UInt64,

    gateway                     LowCardinality(String),
    batch_id                    String,
    ingest_time                 DateTime64(3, 'UTC'),

    os_name                     String,
    os_version                  String,
    os_build                    String,
    os_platform                 LowCardinality(String),
    os_codename                 LowCardinality(String),
    os_family                   LowCardinality(String),

    kernel_name                 String,
    kernel_release              String,
    kernel_version              String,
    kernel_architecture         LowCardinality(String),

    package_name                String,
    package_version             String,
    package_architecture        LowCardinality(String),
    package_manager             LowCardinality(String),
    package_source              String,
    package_vendor              String,
    package_size_bytes          UInt64,
    package_installed_at        DateTime64(3, 'UTC'),

    service_name                String,
    service_display_name        String,
    service_state               LowCardinality(String),
    service_start_mode          LowCardinality(String),
    service_path                String,

    interface_name              String,
    interface_mac               String,
    interface_addresses         Array(String),
    interface_state             LowCardinality(String),
    interface_mtu               UInt32,
    interface_type              LowCardinality(String),

    user_name                   String,
    user_uid                    String,
    user_gid                    String,
    user_home                   String,
    user_shell                  String,
    user_groups                 Array(String),
    user_last_login             DateTime64(3, 'UTC'),

    hardware_cpu_name           String,
    hardware_cpu_cores          UInt32,
    hardware_cpu_mhz            UInt32,
    hardware_memory_total_bytes UInt64,
    hardware_serial             String,
    hardware_vendor             String,
    hardware_model              String,

    process_pid                 UInt32,
    process_parent_pid          UInt32,
    process_name                String,
    process_path                String,
    process_command_line        String,
    process_user                String,
    process_started_at          DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, agent_id, kind, item_id)
TTL toDateTime(last_seen) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

-- When one asset's inventory of one kind was last enumerated in full, which is
-- the only thing that makes absence mean anything: a delta says nothing about
-- what it omits, so only a snapshot moves this line, and an empty snapshot moves
-- it too, which is how a collector says the asset has none of that kind left.
--
-- It is also the staleness of the answer: an asset whose scanned_at is nine days
-- old is reporting a nine-day-old package list, and the reader can see that
-- rather than assume it is current.

CREATE TABLE IF NOT EXISTS asset_inventory_scans
(
    tenant_id  LowCardinality(String),
    agent_id   LowCardinality(String),
    kind       LowCardinality(String),
    scanned_at DateTime64(3, 'UTC'),
    record_id  String,
    items      UInt32
)
ENGINE = ReplacingMergeTree(scanned_at)
ORDER BY (tenant_id, agent_id, kind)
TTL toDateTime(scanned_at) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192
