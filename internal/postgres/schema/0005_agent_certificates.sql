-- Every certificate the platform signed for an agent, append only. The registry
-- row carries the one that is current; this carries the ones that were, so which
-- key a machine held at a past moment survives a renewal.
CREATE TABLE IF NOT EXISTS agent_certificates
(
    fingerprint       TEXT        PRIMARY KEY,
    agent_id          TEXT        NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
    serial            TEXT        NOT NULL,
    subject           TEXT        NOT NULL,
    authority_subject TEXT        NOT NULL DEFAULT '',
    issued_by         TEXT        NOT NULL,
    issued_at         TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    superseded_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS agent_certificates_by_agent
    ON agent_certificates (agent_id, issued_at DESC);

-- An agent holds one current certificate, so superseding the one before it is
-- part of issuing rather than a sweep somebody has to remember to run.
CREATE UNIQUE INDEX IF NOT EXISTS agent_certificates_current
    ON agent_certificates (agent_id) WHERE superseded_at IS NULL;
