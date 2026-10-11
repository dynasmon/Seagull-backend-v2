-- Every policy published into a tenant, append only, with the envelope it is
-- served as. The revision increases across the tenant whichever policy_id it
-- carries, so the key is also the order the tenant's policies were published in,
-- and a newer revision is the only way anything here changes.
CREATE TABLE IF NOT EXISTS agent_policies
(
    tenant_id     TEXT        NOT NULL,
    revision      BIGINT      NOT NULL CHECK (revision > 0),
    policy_id     TEXT        NOT NULL,
    envelope      BYTEA       NOT NULL,
    digest_sha256 TEXT        NOT NULL,
    signed_by     TEXT[]      NOT NULL,
    targets       INTEGER     NOT NULL CHECK (targets > 0),
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    published_by  TEXT        NOT NULL,
    published_at  TIMESTAMPTZ NOT NULL,
    note          TEXT        NOT NULL DEFAULT '',

    PRIMARY KEY (tenant_id, revision)
);

-- Which agents each revision names. An agent is handed the highest revision of
-- its tenant that names it, which the key answers by reading backwards from the
-- agent, without touching a policy it is not handed.
CREATE TABLE IF NOT EXISTS agent_policy_targets
(
    tenant_id TEXT   NOT NULL,
    revision  BIGINT NOT NULL,
    agent_id  TEXT   NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,

    PRIMARY KEY (agent_id, revision),
    FOREIGN KEY (tenant_id, revision) REFERENCES agent_policies (tenant_id, revision) ON DELETE CASCADE
);
