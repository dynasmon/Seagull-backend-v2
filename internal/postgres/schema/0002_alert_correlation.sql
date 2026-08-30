ALTER TABLE alerts ADD COLUMN IF NOT EXISTS correlation_key TEXT   NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS occurrences     BIGINT NOT NULL DEFAULT 1 CHECK (occurrences > 0);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS first_seen      TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_seen       TIMESTAMPTZ;

-- An alert raised before folding existed is made of exactly one detection and
-- keyed by itself, so it folds with nothing rather than with everything.
UPDATE alerts SET correlation_key = alert_id WHERE correlation_key = '';
UPDATE alerts SET first_seen = COALESCE(event_time, raised_at) WHERE first_seen IS NULL;
UPDATE alerts SET last_seen  = COALESCE(event_time, raised_at) WHERE last_seen  IS NULL;

ALTER TABLE alerts ALTER COLUMN first_seen SET NOT NULL;
ALTER TABLE alerts ALTER COLUMN last_seen  SET NOT NULL;

-- Deliberately not unique. A window bounds how much one alert absorbs, so
-- activity that resumes long after the last of it is a new piece of work rather
-- than an unbounded count on an old one.
CREATE INDEX IF NOT EXISTS alerts_open_by_key
    ON alerts (tenant_id, correlation_key, last_seen DESC)
    WHERE state NOT IN ('resolved', 'false_positive');

CREATE INDEX IF NOT EXISTS alerts_closed_by_key
    ON alerts (tenant_id, correlation_key, closure_at DESC)
    WHERE state IN ('resolved', 'false_positive');

-- Every detection an alert is made of. Folding raises a count and discards
-- nothing: an investigation reads these to reach the evidence behind the count.
CREATE TABLE IF NOT EXISTS alert_occurrences
(
    alert_id     TEXT        NOT NULL REFERENCES alerts (alert_id) ON DELETE CASCADE,
    detection_id TEXT        NOT NULL,
    event_time   TIMESTAMPTZ NOT NULL,
    folded_at    TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (alert_id, detection_id)
);

-- A detection belongs to at most one alert anywhere, which is what makes a
-- replayed batch fold nothing a second time.
CREATE UNIQUE INDEX IF NOT EXISTS alert_occurrences_by_detection ON alert_occurrences (detection_id);

INSERT INTO alert_occurrences (alert_id, detection_id, event_time, folded_at)
SELECT alert_id, detection_id, COALESCE(event_time, raised_at), raised_at FROM alerts
ON CONFLICT DO NOTHING;
