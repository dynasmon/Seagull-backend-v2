-- Every episode of certificates a renewal had replaced being presented again to
-- renew, one row per agent and certificate in force when it happened. A renewal
-- refused as already replaced opens or observes it under the agent's row lock
-- that decided the refusal; binding another certificate, or the registry no
-- longer admitting the agent, closes it in the transaction that does so. The
-- certificate in force names the episode and never leaves the platform: what
-- reaches the backbone is a finding named by a digest of it.
CREATE TABLE IF NOT EXISTS agent_replaced_certificates
(
    agent_id           TEXT        NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
    in_force           TEXT        NOT NULL CHECK (in_force <> ''),
    opened_at          TIMESTAMPTZ NOT NULL,
    last_observed_at   TIMESTAMPTZ NOT NULL,
    observations       BIGINT      NOT NULL CHECK (observations > 0),
    closure            TEXT        NOT NULL DEFAULT '' CHECK (closure IN ('', 'rebound', 'not_admitted')),
    closed_at          TIMESTAMPTZ,
    decided_at         TIMESTAMPTZ NOT NULL,

    -- What the backbone has been told. The registry is written first and the
    -- findings log after it, so a row where this trails `revision` is a decision
    -- published again rather than lost.
    revision           BIGINT      NOT NULL CHECK (revision > 0),
    published_revision BIGINT      NOT NULL DEFAULT 0,

    PRIMARY KEY (agent_id, in_force),
    CHECK ((closure = '') = (closed_at IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_replaced_certificates_open
    ON agent_replaced_certificates (agent_id) WHERE closed_at IS NULL;

CREATE INDEX IF NOT EXISTS agent_replaced_certificates_unpublished
    ON agent_replaced_certificates (decided_at) WHERE published_revision < revision;

CREATE INDEX IF NOT EXISTS agent_replaced_certificates_by_decision
    ON agent_replaced_certificates (decided_at) WHERE closed_at IS NULL;
