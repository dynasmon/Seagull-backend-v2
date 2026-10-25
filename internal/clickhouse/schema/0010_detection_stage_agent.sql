-- Which agent sent the event of each stage, beside the stage arrays it is read
-- with: an event is stored under its agent as well as its identifier, so this is
-- what traces a story across agents back to the events it was told from.
--
-- A row stored before stages named their agents holds an empty array here, and
-- a reader takes it for a story whose agents were not recorded rather than for a
-- story with no stages.

ALTER TABLE security_detections
    ADD COLUMN IF NOT EXISTS correlation_stage_agent_id Array(LowCardinality(String)) AFTER correlation_stage_event_time
