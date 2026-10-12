-- Every update root published after the one the control plane was configured
-- with, append only, with the envelope it is served as. A version is recorded
-- only as the next one of the chain, so the key is also the order of the chain.
CREATE TABLE IF NOT EXISTS agent_update_roots
(
    version       BIGINT      PRIMARY KEY CHECK (version > 0),
    envelope      BYTEA       NOT NULL,
    digest_sha256 TEXT        NOT NULL,
    signed_by     TEXT[]      NOT NULL,
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    published_by  TEXT        NOT NULL,
    published_at  TIMESTAMPTZ NOT NULL,
    note          TEXT        NOT NULL DEFAULT ''
);

-- Every package the platform was given, kept by its digest and trusted for
-- nothing: an agent checks it against a catalog a role signed.
CREATE TABLE IF NOT EXISTS agent_packages
(
    sha256       BYTEA       PRIMARY KEY CHECK (octet_length(sha256) = 32),
    size         BIGINT      NOT NULL CHECK (size > 0),
    content      BYTEA       NOT NULL CHECK (octet_length(content) = size),
    published_by TEXT        NOT NULL,
    published_at TIMESTAMPTZ NOT NULL
);

-- Every catalog, append only, with the envelope it is served as. The highest
-- version is the one in force, and a newer catalog is the only way anything
-- here changes.
CREATE TABLE IF NOT EXISTS agent_update_catalogs
(
    version       BIGINT      PRIMARY KEY CHECK (version > 0),
    envelope      BYTEA       NOT NULL,
    digest_sha256 TEXT        NOT NULL,
    signed_by     TEXT[]      NOT NULL,
    releases      INTEGER     NOT NULL CHECK (releases >= 0),
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    published_by  TEXT        NOT NULL,
    published_at  TIMESTAMPTZ NOT NULL,
    note          TEXT        NOT NULL DEFAULT ''
);

-- Which versions each catalog names and the packages it names them with, so a
-- version is assigned only while the newest catalog names it, and a package is
-- handed only to an agent assigned a version the newest catalog names it for.
CREATE TABLE IF NOT EXISTS agent_catalog_releases
(
    catalog_version BIGINT NOT NULL REFERENCES agent_update_catalogs (version) ON DELETE CASCADE,
    version         TEXT   NOT NULL,
    sha256          BYTEA  NOT NULL REFERENCES agent_packages (sha256),

    PRIMARY KEY (catalog_version, version, sha256)
);

-- The release the platform wants each agent to run. The platform's decision and
-- never signed: an agent installs it only where a catalog it verified allows,
-- and an agent with no row keeps the release it runs.
CREATE TABLE IF NOT EXISTS agent_release_assignments
(
    agent_id    TEXT        PRIMARY KEY REFERENCES agents (agent_id) ON DELETE CASCADE,
    tenant_id   TEXT        NOT NULL,
    version     TEXT        NOT NULL,
    assigned_by TEXT        NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL,
    note        TEXT        NOT NULL DEFAULT ''
);
