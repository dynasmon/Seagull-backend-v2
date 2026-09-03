-- A story is not an alert, so it is not a row in the alerts table. An alert is
-- one detection somebody owns; an incident is what several events came to
-- together, and it carries what no alert has: the stages, the span they cover,
-- and how far the clocks that ordered them stood apart.
CREATE TABLE IF NOT EXISTS incidents
(
    incident_id            TEXT          PRIMARY KEY,
    schema_version         INTEGER       NOT NULL,
    tenant_id              TEXT          NOT NULL,
    detection_id           TEXT          NOT NULL,

    rule_id                TEXT          NOT NULL,
    rule_revision          BIGINT        NOT NULL,
    rule_name              TEXT          NOT NULL DEFAULT '',
    rule_source_catalogue  TEXT          NOT NULL DEFAULT '',
    rule_source_identifier TEXT          NOT NULL DEFAULT '',
    ruleset_id             TEXT          NOT NULL DEFAULT '',

    severity               TEXT          NOT NULL DEFAULT '',
    confidence             TEXT          NOT NULL DEFAULT '',
    technique_tactic       TEXT          NOT NULL DEFAULT '',
    technique_id           TEXT          NOT NULL DEFAULT '',
    technique_name         TEXT          NOT NULL DEFAULT '',

    event_class            TEXT          NOT NULL DEFAULT '',
    agent_id               TEXT          NOT NULL DEFAULT '',

    stage_name             TEXT[]        NOT NULL,
    stage_event_id         TEXT[]        NOT NULL,
    stage_event_time       TIMESTAMPTZ[] NOT NULL,

    group_field            TEXT[]        NOT NULL DEFAULT '{}',
    group_value            TEXT[]        NOT NULL DEFAULT '{}',
    group_absent           BOOLEAN[]     NOT NULL DEFAULT '{}',

    window_seconds         BIGINT        NOT NULL DEFAULT 0,
    clock_spread_millis    BIGINT        NOT NULL DEFAULT 0,

    first_event_time       TIMESTAMPTZ   NOT NULL,
    last_event_time        TIMESTAMPTZ   NOT NULL,
    raised_at              TIMESTAMPTZ   NOT NULL,

    state                  TEXT          NOT NULL,
    assignee               TEXT          NOT NULL DEFAULT '',
    changed_by             TEXT          NOT NULL,
    changed_at             TIMESTAMPTZ   NOT NULL,
    revision               BIGINT        NOT NULL CHECK (revision > 0),

    closure_state          TEXT          NOT NULL DEFAULT '',
    closure_reason         TEXT          NOT NULL DEFAULT '',
    closure_by             TEXT          NOT NULL DEFAULT '',
    closure_at             TIMESTAMPTZ,

    -- The stage arrays are one table read sideways, so they are the same length
    -- or the story names an event no stage owns. A story with no stage at all is
    -- not a story and never reaches here.
    CHECK (cardinality(stage_name) > 0),
    CHECK (cardinality(stage_name) = cardinality(stage_event_id)),
    CHECK (cardinality(stage_name) = cardinality(stage_event_time)),
    CHECK (cardinality(group_field) = cardinality(group_value)),
    CHECK (cardinality(group_field) = cardinality(group_absent))
);

-- The tenant is the first column of every read: a scope is not a filter a
-- caller supplies, so an incident is never reached without one.
CREATE INDEX IF NOT EXISTS incidents_by_age    ON incidents (tenant_id, raised_at DESC, incident_id DESC);
CREATE INDEX IF NOT EXISTS incidents_by_state  ON incidents (tenant_id, state, raised_at DESC);
CREATE INDEX IF NOT EXISTS incidents_by_holder ON incidents (tenant_id, assignee, raised_at DESC) WHERE assignee <> '';

-- Append only, and one row per revision, so the trail cannot lose a line to a
-- retry and cannot grow one that never happened.
CREATE TABLE IF NOT EXISTS incident_transitions
(
    incident_id TEXT        NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE,
    revision    BIGINT      NOT NULL CHECK (revision > 0),
    from_state  TEXT        NOT NULL DEFAULT '',
    to_state    TEXT        NOT NULL,
    assignee    TEXT        NOT NULL DEFAULT '',
    actor       TEXT        NOT NULL,
    at          TIMESTAMPTZ NOT NULL,
    note        TEXT        NOT NULL DEFAULT '',

    PRIMARY KEY (incident_id, revision)
);
