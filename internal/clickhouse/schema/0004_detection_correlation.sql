-- What an ordered rule found, added to the table the same way 0003 added what a
-- counting rule found: an estate storing detections from before sequences
-- existed gains the columns without losing the rows.
--
-- A row naming no stage is a detection made by a rule that orders nothing, so
-- absence needs no flag of its own. The stage arrays are one table read
-- sideways, exactly as the evidence and group arrays are, and they are ordered
-- as the rule declares its stages rather than by anything the store decides.

ALTER TABLE security_detections
    ADD COLUMN IF NOT EXISTS correlation_window_seconds UInt32,
    ADD COLUMN IF NOT EXISTS correlation_clock_spread_millis Int64,
    ADD COLUMN IF NOT EXISTS correlation_stage_name Array(String),
    ADD COLUMN IF NOT EXISTS correlation_stage_event_id Array(String),
    ADD COLUMN IF NOT EXISTS correlation_stage_event_time Array(DateTime64(3, 'UTC')),
    ADD COLUMN IF NOT EXISTS correlation_group_field Array(String),
    ADD COLUMN IF NOT EXISTS correlation_group_value Array(String),
    ADD COLUMN IF NOT EXISTS correlation_group_absent Array(Bool)
