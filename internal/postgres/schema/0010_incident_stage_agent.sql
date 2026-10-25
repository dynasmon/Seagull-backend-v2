-- Which agent sent the event of each stage, read with the stage arrays: an event
-- is stored under its agent as well as its identifier, so this is what traces a
-- story across agents back to its events. A story opened before stages named
-- their agents holds none, the one width besides one per stage the check allows.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS stage_agent_id TEXT[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(stage_agent_id) = 0 OR cardinality(stage_agent_id) = cardinality(stage_name));
