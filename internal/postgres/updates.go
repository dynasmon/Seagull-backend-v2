package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const (
	agentUpdateRootsTable       = "agent_update_roots"
	agentUpdateCatalogsTable    = "agent_update_catalogs"
	agentReleaseAssignmentTable = "agent_release_assignments"
)

const insertUpdateRoot = `INSERT INTO agent_update_roots
	(version, envelope, digest_sha256, signed_by, issued_at, expires_at, published_by, published_at, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`

const insertUpdateCatalog = `INSERT INTO agent_update_catalogs
	(version, envelope, digest_sha256, signed_by, releases, issued_at, expires_at, published_by, published_at, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

const insertCatalogReleases = `INSERT INTO agent_catalog_releases (catalog_version, version, sha256)
SELECT $1, named.version, named.sha256 FROM unnest($2::text[], $3::bytea[]) AS named (version, sha256)
ON CONFLICT DO NOTHING`

const newestCatalog = `(SELECT max(version) FROM agent_update_catalogs)`

const assignRelease = `INSERT INTO agent_release_assignments (agent_id, tenant_id, version, assigned_by, assigned_at, note)
SELECT unnest($1::text[]), $2, $3, $4, $5, $6
ON CONFLICT (agent_id) DO UPDATE SET
	tenant_id = excluded.tenant_id, version = excluded.version,
	assigned_by = excluded.assigned_by, assigned_at = excluded.assigned_at, note = excluded.note`

// What decides the release an agent is asked to run: a release assigned to it
// one by one, or else its tenant's rollout in force, with whether that rollout
// may move it.
const wantedRelease = `SELECT agents.state, assignments.version,
	rollouts.rollout_id, rollouts.waves, rollouts.version, rollouts.state, rollouts.wave,
	(rollouts.agents = 0 OR EXISTS (SELECT 1 FROM agent_rollout_agents named
		WHERE named.rollout_id = rollouts.rollout_id AND named.agent_id = agents.agent_id))
FROM agents
LEFT JOIN agent_release_assignments assignments ON assignments.agent_id = agents.agent_id
LEFT JOIN agent_rollouts rollouts ON rollouts.tenant_id = agents.tenant_id AND rollouts.state IN ('active', 'paused')
WHERE agents.agent_id = $1`

const servedPackage = `SELECT packages.content
FROM agent_packages packages
WHERE packages.sha256 = $1
AND EXISTS (SELECT 1 FROM agent_catalog_releases releases
	WHERE releases.sha256 = packages.sha256 AND releases.catalog_version = ` + newestCatalog + `)
AND EXISTS (SELECT 1 FROM agent_catalog_releases wanted
	WHERE wanted.version = $2 AND wanted.catalog_version = ` + newestCatalog + `)`

type AgentUpdates struct {
	store *Store
}

func (s *Store) AgentUpdates() *AgentUpdates { return &AgentUpdates{store: s} }

// The roots recorded after a version, oldest first, as they are served.
func (u *AgentUpdates) Roots(ctx context.Context, after uint64) ([][]byte, error) {
	rows, err := u.store.pool.Query(ctx,
		"SELECT envelope FROM agent_update_roots WHERE version > $1 ORDER BY version", int64(min(after, agentupdate.MaxVersion)))
	if err != nil {
		return nil, fmt.Errorf("read the update roots after %d: %w", after, err)
	}
	roots, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	if err != nil {
		return nil, fmt.Errorf("read the update roots after %d: %w", after, err)
	}
	return roots, nil
}

// Under the chain's lock, so two roots racing are ordered: the second is
// compared with the version the first recorded.
func (u *AgentUpdates) PublishRoot(ctx context.Context, accepted agentupdate.AcceptedRoot) (*updatev1.PublishedRoot, error) {
	record := accepted.Record
	transaction, err := u.store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin publishing root %d: %w", record.GetVersion(), err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	if _, err := transaction.Exec(ctx, holdKey, agentUpdateRootsTable, "chain"); err != nil {
		return nil, fmt.Errorf("hold the update roots: %w", err)
	}
	var highest int64
	if err := transaction.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM agent_update_roots").Scan(&highest); err != nil {
		return nil, fmt.Errorf("read the newest update root: %w", err)
	}
	if record.GetVersion() <= uint64(highest) {
		return nil, fmt.Errorf("%w: the platform holds root %d, and this is root %d", agentupdate.ErrStale, highest, record.GetVersion())
	}
	if _, err := transaction.Exec(ctx, insertUpdateRoot,
		int64(record.GetVersion()), accepted.Root.Served(), record.GetDigestSha256(), record.GetSignedBy(),
		record.GetIssuedAt().AsTime().UTC(), record.GetExpiresAt().AsTime().UTC(),
		record.GetPublishedBy(), record.GetPublishedAt().AsTime().UTC(), record.GetNote(),
	); err != nil {
		if duplicate(err) {
			return nil, fmt.Errorf("%w: the platform already holds root %d", agentupdate.ErrStale, record.GetVersion())
		}
		return nil, fmt.Errorf("record root %d: %w", record.GetVersion(), err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit root %d: %w", record.GetVersion(), err)
	}
	return record, nil
}

// A package given twice is kept once, and answered with what was recorded the
// first time it was given.
func (u *AgentUpdates) PublishPackage(ctx context.Context, accepted agentupdate.AcceptedPackage) (*updatev1.PublishedPackage, error) {
	record := accepted.Record
	tag, err := u.store.pool.Exec(ctx,
		`INSERT INTO agent_packages (sha256, size, content, published_by, published_at)
		VALUES ($1,$2,$3,$4,$5) ON CONFLICT (sha256) DO NOTHING`,
		record.GetSha256(), int64(record.GetSize()), accepted.Content,
		record.GetPublishedBy(), record.GetPublishedAt().AsTime().UTC())
	if err != nil {
		return nil, fmt.Errorf("record package %s: %w", hex.EncodeToString(record.GetSha256()), err)
	}
	if tag.RowsAffected() == 1 {
		return record, nil
	}

	var (
		size        int64
		publishedAt time.Time
		held        = &updatev1.PublishedPackage{Sha256: record.GetSha256()}
	)
	if err := u.store.pool.QueryRow(ctx,
		"SELECT size, published_by, published_at FROM agent_packages WHERE sha256 = $1", record.GetSha256(),
	).Scan(&size, &held.PublishedBy, &publishedAt); err != nil {
		return nil, fmt.Errorf("read package %s: %w", hex.EncodeToString(record.GetSha256()), err)
	}
	held.Size = uint64(size)
	held.PublishedAt = timestamppb.New(publishedAt.UTC())
	return held, nil
}

// Under the catalogs' lock, so two catalogs racing are ordered, and with every
// package it names read inside the same transaction.
func (u *AgentUpdates) PublishCatalog(ctx context.Context, accepted agentupdate.AcceptedCatalog) (*updatev1.PublishedCatalog, error) {
	record := accepted.Record
	transaction, err := u.store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin publishing catalog %d: %w", record.GetVersion(), err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	if _, err := transaction.Exec(ctx, holdKey, agentUpdateCatalogsTable, "catalog"); err != nil {
		return nil, fmt.Errorf("hold the update catalogs: %w", err)
	}
	var highest int64
	if err := transaction.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM agent_update_catalogs").Scan(&highest); err != nil {
		return nil, fmt.Errorf("read the newest update catalog: %w", err)
	}
	if record.GetVersion() <= uint64(highest) {
		return nil, fmt.Errorf("%w: the platform holds catalog %d, and this is catalog %d", agentupdate.ErrStale, highest, record.GetVersion())
	}

	digests := make([][]byte, 0, len(accepted.Packages))
	for _, held := range accepted.Packages {
		digests = append(digests, held.Sha256)
	}
	rows, err := transaction.Query(ctx, "SELECT sha256, size FROM agent_packages WHERE sha256 = ANY($1)", digests)
	if err != nil {
		return nil, fmt.Errorf("read the packages catalog %d names: %w", record.GetVersion(), err)
	}
	given, err := pgx.CollectRows(rows, pgx.RowToStructByPos[storedPackage])
	if err != nil {
		return nil, fmt.Errorf("read the packages catalog %d names: %w", record.GetVersion(), err)
	}
	if missing := ungiven(accepted.Packages, given); len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", agentupdate.ErrNoPackage, listed(missing))
	}

	if _, err := transaction.Exec(ctx, insertUpdateCatalog,
		int64(record.GetVersion()), accepted.Catalog.Served(), record.GetDigestSha256(), record.GetSignedBy(),
		int32(record.GetReleases()), record.GetIssuedAt().AsTime().UTC(), record.GetExpiresAt().AsTime().UTC(),
		record.GetPublishedBy(), record.GetPublishedAt().AsTime().UTC(), record.GetNote(),
	); err != nil {
		if duplicate(err) {
			return nil, fmt.Errorf("%w: the platform already holds catalog %d", agentupdate.ErrStale, record.GetVersion())
		}
		return nil, fmt.Errorf("record catalog %d: %w", record.GetVersion(), err)
	}
	var versions []string
	var payloads [][]byte
	for _, release := range accepted.Catalog.Releases() {
		versions = append(versions, release.GetVersion())
		payloads = append(payloads, release.GetPayload().GetSha256())
	}
	if _, err := transaction.Exec(ctx, insertCatalogReleases, int64(record.GetVersion()), versions, payloads); err != nil {
		return nil, fmt.Errorf("record the releases catalog %d names: %w", record.GetVersion(), err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit catalog %d: %w", record.GetVersion(), err)
	}
	return record, nil
}

type storedPackage struct {
	Sha256 []byte
	Size   int64
}

func ungiven(named []agentupdate.Package, given []storedPackage) []string {
	var missing []string
	for _, wanted := range named {
		found := false
		for _, held := range given {
			found = found || (bytes.Equal(held.Sha256, wanted.Sha256) && uint64(held.Size) == wanted.Size)
		}
		if !found {
			missing = append(missing, hex.EncodeToString(wanted.Sha256))
		}
	}
	return missing
}

// Under the tenant's assignment lock, with the newest catalog and every agent
// it names read inside the same transaction, since either can change between
// the request and the record.
func (u *AgentUpdates) Assign(ctx context.Context, accepted agentupdate.AcceptedAssignment) (*updatev1.Assigned, error) {
	record := accepted.Record
	transaction, err := u.store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin assigning agents of %s: %w", accepted.TenantID, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	if _, err := transaction.Exec(ctx, holdKey, agentReleaseAssignmentTable, accepted.TenantID); err != nil {
		return nil, fmt.Errorf("hold the assignments of %s: %w", accepted.TenantID, err)
	}
	if accepted.Version != "" {
		var cataloged bool
		if err := transaction.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM agent_catalog_releases WHERE catalog_version = "+newestCatalog+" AND version = $1)",
			accepted.Version,
		).Scan(&cataloged); err != nil {
			return nil, fmt.Errorf("read whether the newest catalog names %s: %w", accepted.Version, err)
		}
		if !cataloged {
			return nil, fmt.Errorf("%w: %s", agentupdate.ErrUncataloged, accepted.Version)
		}
	}

	rows, err := transaction.Query(ctx,
		"SELECT agent_id FROM agents WHERE tenant_id = $1 AND agent_id = ANY($2)", accepted.TenantID, accepted.AgentIDs)
	if err != nil {
		return nil, fmt.Errorf("read the agents an assignment names: %w", err)
	}
	registered, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("read the agents an assignment names: %w", err)
	}
	if missing := unregistered(accepted.AgentIDs, registered); len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", agentupdate.ErrUnregistered, listed(missing))
	}

	if accepted.Version == "" {
		_, err = transaction.Exec(ctx, "DELETE FROM agent_release_assignments WHERE agent_id = ANY($1)", accepted.AgentIDs)
	} else {
		_, err = transaction.Exec(ctx, assignRelease, accepted.AgentIDs, accepted.TenantID, accepted.Version,
			record.GetAssignedBy(), record.GetAssignedAt().AsTime().UTC(), record.GetNote())
	}
	if err != nil {
		return nil, fmt.Errorf("record the assignment of %d agents of %s: %w", len(accepted.AgentIDs), accepted.TenantID, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit the assignment of %d agents of %s: %w", len(accepted.AgentIDs), accepted.TenantID, err)
	}
	return record, nil
}

// An agent asking whether to update is not a caller with a scope: the
// connection proved which agent it is.
func (u *AgentUpdates) Served(ctx context.Context, agentID string, after uint64) (agentupdate.Served, error) {
	state, version, err := u.wanted(ctx, agentID)
	if err != nil {
		return agentupdate.Served{}, err
	}
	served := agentupdate.Served{State: state, Version: version}
	if err := u.store.pool.QueryRow(ctx,
		"SELECT envelope FROM agent_update_catalogs ORDER BY version DESC LIMIT 1").Scan(&served.Catalog); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return agentupdate.Served{}, fmt.Errorf("read the newest update catalog: %w", err)
	}
	if served.Roots, err = u.Roots(ctx, after); err != nil {
		return agentupdate.Served{}, err
	}
	return served, nil
}

// The release an agent is asked to run: the one assigned to it one by one,
// whatever its tenant's rollout says, or else the one that rollout asks of it.
func (u *AgentUpdates) wanted(ctx context.Context, agentID string) (agent.State, string, error) {
	var (
		state                        string
		assigned, rolloutID, version *string
		waves                        []byte
		rolloutState                 *string
		wave                         *int32
		member                       *bool
	)
	err := u.store.pool.QueryRow(ctx, wantedRelease, agentID).Scan(
		&state, &assigned, &rolloutID, &waves, &version, &rolloutState, &wave, &member)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", "", agent.ErrUnknown
	case err != nil:
		return "", "", fmt.Errorf("read the release agent %s is asked to run: %w", agentID, err)
	}
	var (
		named  string
		record *updatev1.RolloutRecord
	)
	if assigned != nil {
		named = *assigned
	}
	if rolloutID != nil {
		var opened updatev1.Rollout
		if err := proto.Unmarshal(waves, &opened); err != nil {
			return "", "", fmt.Errorf("read the waves of rollout %s: %w", *rolloutID, err)
		}
		held, _ := agentupdate.ParseState(*rolloutState)
		record = &updatev1.RolloutRecord{
			RolloutId: *rolloutID,
			Rollout:   &updatev1.Rollout{Version: *version, Waves: opened.GetWaves()},
			State:     held,
			Wave:      uint32(*wave),
		}
	}
	return agent.State(state), agentupdate.Wanted(named, record, member != nil && *member, agentID), nil
}

// A package is read only for an agent the platform still listens to, asked to
// run a version the newest catalog names, and only when that catalog names the
// package: the release the agent is to run or the one it would go back to.
func (u *AgentUpdates) Package(ctx context.Context, agentID string, digest []byte) (agentupdate.ServedPackage, error) {
	state, version, err := u.wanted(ctx, agentID)
	if err != nil {
		return agentupdate.ServedPackage{}, err
	}
	served := agentupdate.ServedPackage{State: state}
	if !served.State.Admits() {
		return served, nil
	}
	if version == "" {
		return agentupdate.ServedPackage{}, agentupdate.ErrUnknown
	}
	err = u.store.pool.QueryRow(ctx, servedPackage, digest, version).Scan(&served.Content)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return agentupdate.ServedPackage{}, agentupdate.ErrUnknown
	case err != nil:
		return agentupdate.ServedPackage{}, fmt.Errorf("read package %s for agent %s: %w", hex.EncodeToString(digest), agentID, err)
	}
	return served, nil
}
