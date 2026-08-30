CREATE TABLE IF NOT EXISTS alerts
(
    alert_id               TEXT        PRIMARY KEY,
    schema_version         INTEGER     NOT NULL,
    tenant_id              TEXT        NOT NULL,
    detection_id           TEXT        NOT NULL,

    rule_id                TEXT        NOT NULL,
    rule_revision          BIGINT      NOT NULL,
    rule_name              TEXT        NOT NULL DEFAULT '',
    rule_source_catalogue  TEXT        NOT NULL DEFAULT '',
    rule_source_identifier TEXT        NOT NULL DEFAULT '',

    severity               TEXT        NOT NULL DEFAULT '',
    technique_tactic       TEXT        NOT NULL DEFAULT '',
    technique_id           TEXT        NOT NULL DEFAULT '',
    technique_name         TEXT        NOT NULL DEFAULT '',

    event_class            TEXT        NOT NULL DEFAULT '',
    agent_id               TEXT        NOT NULL DEFAULT '',

    event_time             TIMESTAMPTZ,
    raised_at              TIMESTAMPTZ NOT NULL,

    state                  TEXT        NOT NULL,
    assignee               TEXT        NOT NULL DEFAULT '',
    changed_by             TEXT        NOT NULL,
    changed_at             TIMESTAMPTZ NOT NULL,
    revision               BIGINT      NOT NULL CHECK (revision > 0),

    closure_state          TEXT        NOT NULL DEFAULT '',
    closure_reason         TEXT        NOT NULL DEFAULT '',
    closure_by             TEXT        NOT NULL DEFAULT '',
    closure_at             TIMESTAMPTZ
);

-- The tenant is the first column of every read: a scope is not a filter a
-- caller supplies, so an alert is never reached without one.
CREATE INDEX IF NOT EXISTS alerts_by_age    ON alerts (tenant_id, raised_at DESC, alert_id DESC);
CREATE INDEX IF NOT EXISTS alerts_by_state  ON alerts (tenant_id, state, raised_at DESC);
CREATE INDEX IF NOT EXISTS alerts_by_holder ON alerts (tenant_id, assignee, raised_at DESC) WHERE assignee <> '';

-- Append only, and one row per revision, so the trail cannot lose a line to a
-- retry and cannot grow one that never happened.
CREATE TABLE IF NOT EXISTS alert_transitions
(
    alert_id   TEXT        NOT NULL REFERENCES alerts (alert_id) ON DELETE CASCADE,
    revision   BIGINT      NOT NULL CHECK (revision > 0),
    from_state TEXT        NOT NULL DEFAULT '',
    to_state   TEXT        NOT NULL,
    assignee   TEXT        NOT NULL DEFAULT '',
    actor      TEXT        NOT NULL,
    at         TIMESTAMPTZ NOT NULL,
    note       TEXT        NOT NULL DEFAULT '',

    PRIMARY KEY (alert_id, revision)
);
