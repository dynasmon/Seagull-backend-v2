-- What a counting rule found, added to a table that already exists rather than
-- written into 0002: an estate that has been storing detections since before
-- thresholds existed must gain the columns without losing the rows.
--
-- Absence is the zero value, as in proto3, so a detection made by a rule that
-- counts nothing reads as a count of zero against a threshold of zero. The three
-- group arrays are one table read sideways, exactly as the evidence arrays are.

ALTER TABLE security_detections
    ADD COLUMN IF NOT EXISTS aggregation_count UInt32,
    ADD COLUMN IF NOT EXISTS aggregation_threshold UInt32,
    ADD COLUMN IF NOT EXISTS aggregation_window_seconds UInt32,
    ADD COLUMN IF NOT EXISTS aggregation_first_event_time DateTime64(3, 'UTC'),
    ADD COLUMN IF NOT EXISTS aggregation_saturated Bool,
    ADD COLUMN IF NOT EXISTS aggregation_group_field Array(String),
    ADD COLUMN IF NOT EXISTS aggregation_group_value Array(String),
    ADD COLUMN IF NOT EXISTS aggregation_group_absent Array(Bool)
