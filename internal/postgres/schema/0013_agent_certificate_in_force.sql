-- The certificate a binding replaced and when, which a listener admits for a
-- short tolerance once it learns of the replacement; and the shape of the
-- admission record the log was last told, so every agent's record is written
-- again once it carries the certificate in force, without counting as a decision
-- the data plane was never told.
ALTER TABLE agents
    ADD COLUMN replaced_fingerprint TEXT        NOT NULL DEFAULT '',
    ADD COLUMN replaced_at          TIMESTAMPTZ,
    ADD COLUMN published_format     SMALLINT    NOT NULL DEFAULT 0;

CREATE INDEX agents_unwritten ON agents (agent_id) WHERE published_format < 1;

-- The route of the agent listener a replaced certificate was last refused on,
-- empty for a renewal, which is the only route an episode opened on before.
ALTER TABLE agent_replaced_certificates
    ADD COLUMN use_route TEXT NOT NULL DEFAULT '';
