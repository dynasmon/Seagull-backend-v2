CREATE TABLE IF NOT EXISTS agents
(
    agent_id              TEXT        PRIMARY KEY,
    schema_version        INTEGER     NOT NULL,
    tenant_id             TEXT        NOT NULL,

    state                 TEXT        NOT NULL,

    platform_os           TEXT        NOT NULL DEFAULT '',
    platform_architecture TEXT        NOT NULL DEFAULT '',
    platform_hostname     TEXT        NOT NULL DEFAULT '',
    agent_version         TEXT        NOT NULL DEFAULT '',

    identity_subject      TEXT        NOT NULL DEFAULT '',
    identity_serial       TEXT        NOT NULL DEFAULT '',
    identity_fingerprint  TEXT        NOT NULL DEFAULT '',
    identity_issued_at    TIMESTAMPTZ,
    identity_expires_at   TIMESTAMPTZ,

    registered_at         TIMESTAMPTZ NOT NULL,
    changed_by            TEXT        NOT NULL,
    changed_at            TIMESTAMPTZ NOT NULL,
    revision              BIGINT      NOT NULL CHECK (revision > 0),

    -- What the data plane has been told. The registry is written first and the
    -- admission log after it, so a row where this trails `revision` is a
    -- decision the gateway has not heard and is published again rather than
    -- lost.
    published_revision    BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS agents_unannounced
    ON agents (changed_at) WHERE published_revision < revision;

-- The tenant is the first column of every read: a scope is not a filter a
-- caller supplies, so an agent is never reached without one.
CREATE INDEX IF NOT EXISTS agents_by_name  ON agents (tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS agents_by_state ON agents (tenant_id, state, agent_id);

-- One certificate belongs to one agent. Two agents claiming the same
-- fingerprint would make a revocation ambiguous, and an operator binding a
-- certificate that is already somebody else's is refused rather than recorded.
CREATE UNIQUE INDEX IF NOT EXISTS agents_by_certificate
    ON agents (identity_fingerprint) WHERE identity_fingerprint <> '';

-- Append only, and one row per revision, so the trail cannot lose a line to a
-- retry and cannot grow one that never happened.
CREATE TABLE IF NOT EXISTS agent_transitions
(
    agent_id   TEXT        NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
    revision   BIGINT      NOT NULL CHECK (revision > 0),
    from_state TEXT        NOT NULL DEFAULT '',
    to_state   TEXT        NOT NULL,
    actor      TEXT        NOT NULL,
    at         TIMESTAMPTZ NOT NULL,
    note       TEXT        NOT NULL DEFAULT '',

    PRIMARY KEY (agent_id, revision)
);
