-- Every rollout an operator started, with the wave it reached and what the
-- platform last read of the agents it reached. A tenant has at most one
-- rollout in force, active or paused: a new one takes over from it under the
-- tenant's lock, and a rollout that ended is kept as it ended.
--
-- `rollout` is the seagull.update.v1.Rollout as it was taken. `waves` holds its
-- waves alone, encoded as a Rollout of nothing else, which is what an agent
-- asking whether to update is placed by, and the agents it names one by one
-- are rows of agent_rollout_agents; `agents` says how many it named, and none
-- names every agent of the tenant.
CREATE TABLE IF NOT EXISTS agent_rollouts
(
    rollout_id     TEXT        PRIMARY KEY,
    tenant_id      TEXT        NOT NULL,
    version        TEXT        NOT NULL,
    failures       INTEGER     NOT NULL CHECK (failures > 0),
    note           TEXT        NOT NULL DEFAULT '',
    waves          BYTEA       NOT NULL,
    agents         INTEGER     NOT NULL CHECK (agents >= 0),
    rollout        BYTEA       NOT NULL,

    state          TEXT        NOT NULL CHECK (state IN ('active', 'paused', 'aborted', 'superseded')),
    wave           INTEGER     NOT NULL CHECK (wave >= 0),
    wave_opened_at TIMESTAMPTZ NOT NULL,

    -- How many times its state or its wave changed, so what the platform read
    -- before an operator changed it is never written over that change.
    changes        BIGINT      NOT NULL DEFAULT 0 CHECK (changes >= 0),

    created_by     TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    changed_by     TEXT        NOT NULL,
    changed_at     TIMESTAMPTZ NOT NULL,
    reason         TEXT        NOT NULL DEFAULT '',

    -- The seagull.update.v1.RolloutProgress the platform last read, absent
    -- until it first did.
    progress       BYTEA
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_rollouts_in_force
    ON agent_rollouts (tenant_id) WHERE state IN ('active', 'paused');
CREATE INDEX IF NOT EXISTS agent_rollouts_by_tenant
    ON agent_rollouts (tenant_id, created_at DESC, rollout_id);

-- The agents a rollout names one by one, so an agent asking whether to update
-- learns whether its tenant's rollout names it without the rollout being read
-- whole.
CREATE TABLE IF NOT EXISTS agent_rollout_agents
(
    rollout_id TEXT NOT NULL REFERENCES agent_rollouts (rollout_id) ON DELETE CASCADE,
    agent_id   TEXT NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,

    PRIMARY KEY (rollout_id, agent_id)
);

-- The agents the platform last read as failing a rollout's release, written
-- with every reading, which is what an operator resuming the rollout takes as
-- known.
CREATE TABLE IF NOT EXISTS agent_rollout_failing
(
    rollout_id TEXT NOT NULL REFERENCES agent_rollouts (rollout_id) ON DELETE CASCADE,
    agent_id   TEXT NOT NULL,

    PRIMARY KEY (rollout_id, agent_id)
);

-- The agents whose failure an operator resumed a rollout past, which no
-- longer count toward pausing it.
CREATE TABLE IF NOT EXISTS agent_rollout_acknowledged
(
    rollout_id TEXT NOT NULL REFERENCES agent_rollouts (rollout_id) ON DELETE CASCADE,
    agent_id   TEXT NOT NULL,

    PRIMARY KEY (rollout_id, agent_id)
);
