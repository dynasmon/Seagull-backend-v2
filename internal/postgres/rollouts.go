package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const agentRolloutsTable = "agent_rollouts"

const rolloutColumns = `rollout_id, tenant_id, version, failures, note, waves, agents, state, wave, wave_opened_at,
	changes, created_by, created_at, changed_by, changed_at, reason, progress`

const insertRollout = `INSERT INTO agent_rollouts
	(rollout_id, tenant_id, version, failures, note, waves, agents, rollout, state, wave, wave_opened_at,
	changes, created_by, created_at, changed_by, changed_at, reason)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',0,$9,0,$10,$11,$12,$13,$14)`

const supersedeRollout = `UPDATE agent_rollouts
SET state = 'superseded', changes = changes + 1, changed_by = $2, changed_at = $3, reason = $4
WHERE tenant_id = $1 AND state IN ('active', 'paused')`

// The agents of the tenant a rollout may move that the platform still listens
// to, each with whether a release was assigned to it one by one.
const rolloutReach = `SELECT agents.agent_id, assignments.agent_id IS NOT NULL
FROM agents
LEFT JOIN agent_release_assignments assignments ON assignments.agent_id = agents.agent_id
WHERE agents.tenant_id = $1 AND agents.state IN ('pending', 'active')
AND ($2 OR EXISTS (SELECT 1 FROM agent_rollout_agents named WHERE named.rollout_id = $3 AND named.agent_id = agents.agent_id))
ORDER BY agents.agent_id`

type AgentRollouts struct {
	store *Store
}

func (s *Store) AgentRollouts() *AgentRollouts { return &AgentRollouts{store: s} }

// Under the tenant's assignment lock, which is the one an assignment takes, so
// a rollout and an assignment racing are ordered; with the newest catalog and
// every agent it names read inside the same transaction. The rollout in force
// is superseded by the one that takes over from it.
func (r *AgentRollouts) Start(ctx context.Context, accepted agentupdate.AcceptedRollout) (*updatev1.RolloutRecord, error) {
	record, rollout := accepted.Record, accepted.Rollout()
	tenant := rollout.GetTenantId()
	transaction, err := r.store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin starting a rollout of %s: %w", tenant, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	if _, err := transaction.Exec(ctx, holdKey, agentReleaseAssignmentTable, tenant); err != nil {
		return nil, fmt.Errorf("hold the assignments of %s: %w", tenant, err)
	}
	var cataloged bool
	if err := transaction.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM agent_catalog_releases WHERE catalog_version = "+newestCatalog+" AND version = $1)",
		rollout.GetVersion(),
	).Scan(&cataloged); err != nil {
		return nil, fmt.Errorf("read whether the newest catalog names %s: %w", rollout.GetVersion(), err)
	}
	if !cataloged {
		return nil, fmt.Errorf("%w: %s", agentupdate.ErrUncataloged, rollout.GetVersion())
	}

	named := slices.Clone(rollout.GetAgentIds())
	for _, wave := range rollout.GetWaves() {
		named = append(named, wave.GetAgentIds()...)
	}
	slices.Sort(named)
	named = slices.Compact(named)
	if len(named) > 0 {
		rows, err := transaction.Query(ctx,
			"SELECT agent_id FROM agents WHERE tenant_id = $1 AND agent_id = ANY($2)", tenant, named)
		if err != nil {
			return nil, fmt.Errorf("read the agents a rollout names: %w", err)
		}
		registered, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return nil, fmt.Errorf("read the agents a rollout names: %w", err)
		}
		if missing := unregistered(named, registered); len(missing) > 0 {
			return nil, fmt.Errorf("%w: %s", agentupdate.ErrUnregistered, listed(missing))
		}
	}

	at := record.GetCreatedAt().AsTime().UTC()
	if _, err := transaction.Exec(ctx, supersedeRollout, tenant, record.GetCreatedBy(), at,
		"rollout "+record.GetRolloutId()+" took over"); err != nil {
		return nil, fmt.Errorf("supersede the rollout in force in %s: %w", tenant, err)
	}
	waves, whole, err := encodedRollout(rollout)
	if err != nil {
		return nil, err
	}
	if _, err := transaction.Exec(ctx, insertRollout,
		record.GetRolloutId(), tenant, rollout.GetVersion(), int32(rollout.GetFailures()), rollout.GetNote(),
		waves, int32(len(rollout.GetAgentIds())), whole, at,
		record.GetCreatedBy(), at, record.GetChangedBy(), at, record.GetReason(),
	); err != nil {
		return nil, fmt.Errorf("record rollout %s: %w", record.GetRolloutId(), err)
	}
	if ids := rollout.GetAgentIds(); len(ids) > 0 {
		if _, err := transaction.Exec(ctx,
			"INSERT INTO agent_rollout_agents (rollout_id, agent_id) SELECT $1, unnest($2::text[])",
			record.GetRolloutId(), ids); err != nil {
			return nil, fmt.Errorf("record the agents rollout %s names: %w", record.GetRolloutId(), err)
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit rollout %s: %w", record.GetRolloutId(), err)
	}
	return record, nil
}

// The waves a rollout opens, encoded as a rollout of nothing else, and the
// rollout whole.
func encodedRollout(rollout *updatev1.Rollout) ([]byte, []byte, error) {
	deterministic := proto.MarshalOptions{Deterministic: true}
	waves, err := deterministic.Marshal(&updatev1.Rollout{Waves: rollout.GetWaves()})
	if err != nil {
		return nil, nil, fmt.Errorf("encode the waves of the rollout: %w", err)
	}
	whole, err := deterministic.Marshal(rollout)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the rollout: %w", err)
	}
	return waves, whole, nil
}

// Under the tenant's assignment lock, so an operator's change and a rollout
// taking over from this one are ordered.
func (r *AgentRollouts) Change(ctx context.Context, accepted agentupdate.AcceptedChange) (*updatev1.RolloutRecord, error) {
	transaction, err := r.store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin changing rollout %s: %w", accepted.RolloutID, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	if _, err := transaction.Exec(ctx, holdKey, agentReleaseAssignmentTable, accepted.TenantID); err != nil {
		return nil, fmt.Errorf("hold the assignments of %s: %w", accepted.TenantID, err)
	}
	rows, err := transaction.Query(ctx,
		"SELECT "+rolloutColumns+" FROM agent_rollouts WHERE tenant_id = $1 AND rollout_id = $2 FOR UPDATE",
		accepted.TenantID, accepted.RolloutID)
	if err != nil {
		return nil, fmt.Errorf("read rollout %s: %w", accepted.RolloutID, err)
	}
	found, err := pgx.CollectRows(rows, restoringRollout)
	if err != nil {
		return nil, fmt.Errorf("read rollout %s: %w", accepted.RolloutID, err)
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("%w: %s", agentupdate.ErrRolloutUnknown, accepted.RolloutID)
	}
	held := found[0]
	changed, acknowledge, err := accepted.Apply(held.Record)
	if err != nil {
		return nil, err
	}
	if _, err := transaction.Exec(ctx, `UPDATE agent_rollouts
		SET state = $2, wave = $3, wave_opened_at = $4,
			changes = changes + 1, changed_by = $5, changed_at = $6, reason = $7
		WHERE rollout_id = $1`,
		accepted.RolloutID, agentupdate.StateName(changed.GetState()), int32(changed.GetWave()),
		changed.GetWaveOpenedAt().AsTime().UTC(),
		changed.GetChangedBy(), changed.GetChangedAt().AsTime().UTC(), changed.GetReason(),
	); err != nil {
		return nil, fmt.Errorf("record the change of rollout %s: %w", accepted.RolloutID, err)
	}
	if acknowledge {
		if _, err := transaction.Exec(ctx, `INSERT INTO agent_rollout_acknowledged (rollout_id, agent_id)
			SELECT rollout_id, agent_id FROM agent_rollout_failing WHERE rollout_id = $1 ON CONFLICT DO NOTHING`,
			accepted.RolloutID); err != nil {
			return nil, fmt.Errorf("take the failures of rollout %s as known: %w", accepted.RolloutID, err)
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit the change of rollout %s: %w", accepted.RolloutID, err)
	}
	return changed, nil
}

// The scope is a predicate on every read: tenants a caller names beyond the
// ones they hold answer nothing rather than widening it. A page carries no
// rollout's agents, which a read of the one rollout does.
func (r *AgentRollouts) Page(ctx context.Context, asked *updatev1.RolloutQuery, tenants []string) (*updatev1.RolloutPage, error) {
	limit := int(asked.GetLimit())
	if limit <= 0 {
		limit = DefaultPageSize
	}
	limit = min(limit, MaxPageSize)

	scope := tenants
	if named := asked.GetTenantIds(); len(named) > 0 {
		scope = slices.DeleteFunc(slices.Clone(named), func(tenant string) bool { return !slices.Contains(tenants, tenant) })
	}
	where := []string{"tenant_id = ANY($1)"}
	arguments := []any{scope}
	place := func(value any) string {
		arguments = append(arguments, value)
		return "$" + strconv.Itoa(len(arguments))
	}
	if asked.GetCursor() != "" {
		tenant, created, id, err := decodeRolloutCursor(asked.GetCursor())
		if err != nil {
			return nil, err
		}
		after, at, named := place(tenant), place(created), place(id)
		where = append(where, "(tenant_id > "+after+" OR (tenant_id = "+after+
			" AND (created_at < "+at+" OR (created_at = "+at+" AND rollout_id > "+named+"))))")
	}

	rows, err := r.store.pool.Query(ctx,
		"SELECT "+rolloutColumns+" FROM agent_rollouts WHERE "+strings.Join(where, " AND ")+
			" ORDER BY tenant_id, created_at DESC, rollout_id LIMIT "+place(limit+1), arguments...)
	if err != nil {
		return nil, fmt.Errorf("list agent rollouts: %w", err)
	}
	found, err := pgx.CollectRows(rows, restoringRollout)
	if err != nil {
		return nil, fmt.Errorf("list agent rollouts: %w", err)
	}

	page := &updatev1.RolloutPage{}
	for _, held := range found[:min(len(found), limit)] {
		page.Rollouts = append(page.Rollouts, held.Record)
	}
	if len(found) > limit {
		last := page.Rollouts[limit-1]
		page.NextCursor = encodeRolloutCursor(last.GetRollout().GetTenantId(), last.GetCreatedAt().AsTime(), last.GetRolloutId())
	}
	return page, nil
}

func (r *AgentRollouts) Rollout(ctx context.Context, tenant, id string, tenants []string) (*updatev1.RolloutRecord, error) {
	if !slices.Contains(tenants, tenant) || !agentupdate.ValidRolloutID(id) {
		return nil, agentupdate.ErrRolloutUnknown
	}
	var whole []byte
	rows, err := r.store.pool.Query(ctx,
		"SELECT "+rolloutColumns+", rollout FROM agent_rollouts WHERE tenant_id = $1 AND rollout_id = $2", tenant, id)
	if err != nil {
		return nil, fmt.Errorf("read rollout %s: %w", id, err)
	}
	found, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (agentupdate.Held, error) {
		return scanRollout(row, &whole)
	})
	if err != nil {
		return nil, fmt.Errorf("read rollout %s: %w", id, err)
	}
	if len(found) == 0 {
		return nil, agentupdate.ErrRolloutUnknown
	}
	record := found[0].Record
	var taken updatev1.Rollout
	if err := proto.Unmarshal(whole, &taken); err != nil {
		return nil, fmt.Errorf("read rollout %s: %w", id, err)
	}
	record.Rollout = &taken
	return record, nil
}

// Every rollout in force, for the platform to read how far each went.
func (r *AgentRollouts) InForce(ctx context.Context) ([]agentupdate.Held, error) {
	rows, err := r.store.pool.Query(ctx,
		"SELECT "+rolloutColumns+" FROM agent_rollouts WHERE state IN ('active', 'paused') ORDER BY tenant_id")
	if err != nil {
		return nil, fmt.Errorf("list the rollouts in force: %w", err)
	}
	held, err := pgx.CollectRows(rows, restoringRollout)
	if err != nil {
		return nil, fmt.Errorf("list the rollouts in force: %w", err)
	}
	return held, nil
}

func (r *AgentRollouts) Reach(ctx context.Context, held agentupdate.Held) (agentupdate.Reach, error) {
	record := held.Record
	whole := !held.Named
	rows, err := r.store.pool.Query(ctx, rolloutReach, record.GetRollout().GetTenantId(), whole, record.GetRolloutId())
	if err != nil {
		return agentupdate.Reach{}, fmt.Errorf("read the agents rollout %s may move: %w", record.GetRolloutId(), err)
	}
	reach := agentupdate.Reach{Pinned: map[string]bool{}, Acknowledged: map[string]bool{}}
	for rows.Next() {
		var (
			id     string
			pinned bool
		)
		if err := rows.Scan(&id, &pinned); err != nil {
			rows.Close()
			return agentupdate.Reach{}, fmt.Errorf("read the agents rollout %s may move: %w", record.GetRolloutId(), err)
		}
		reach.Agents = append(reach.Agents, id)
		if pinned {
			reach.Pinned[id] = true
		}
	}
	if err := rows.Err(); err != nil {
		return agentupdate.Reach{}, fmt.Errorf("read the agents rollout %s may move: %w", record.GetRolloutId(), err)
	}

	known, err := r.store.pool.Query(ctx, "SELECT agent_id FROM agent_rollout_acknowledged WHERE rollout_id = $1", record.GetRolloutId())
	if err != nil {
		return agentupdate.Reach{}, fmt.Errorf("read the failures rollout %s took as known: %w", record.GetRolloutId(), err)
	}
	acknowledged, err := pgx.CollectRows(known, pgx.RowTo[string])
	if err != nil {
		return agentupdate.Reach{}, fmt.Errorf("read the failures rollout %s took as known: %w", record.GetRolloutId(), err)
	}
	for _, id := range acknowledged {
		reach.Acknowledged[id] = true
	}
	return reach, nil
}

// A reading written only while the rollout still stands where it was read, so
// a change an operator made meanwhile is never undone by it. Whether it was
// written is the answer.
func (r *AgentRollouts) Settle(ctx context.Context, settled agentupdate.Settled) (bool, error) {
	record := settled.Record
	progress, err := proto.MarshalOptions{Deterministic: true}.Marshal(record.GetProgress())
	if err != nil {
		return false, fmt.Errorf("encode the progress of rollout %s: %w", record.GetRolloutId(), err)
	}
	transaction, err := r.store.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin settling rollout %s: %w", record.GetRolloutId(), err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	changes := settled.Held.Changes
	if settled.Moved {
		changes++
	}
	tag, err := transaction.Exec(ctx, `UPDATE agent_rollouts
		SET state = $3, wave = $4, wave_opened_at = $5,
			changes = $6, changed_by = $7, changed_at = $8, reason = $9, progress = $10
		WHERE rollout_id = $1 AND changes = $2`,
		record.GetRolloutId(), settled.Held.Changes,
		agentupdate.StateName(record.GetState()), int32(record.GetWave()), record.GetWaveOpenedAt().AsTime().UTC(),
		changes, record.GetChangedBy(), record.GetChangedAt().AsTime().UTC(), record.GetReason(), progress)
	if err != nil {
		return false, fmt.Errorf("settle rollout %s: %w", record.GetRolloutId(), err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if _, err := transaction.Exec(ctx, "DELETE FROM agent_rollout_failing WHERE rollout_id = $1", record.GetRolloutId()); err != nil {
		return false, fmt.Errorf("forget the failures rollout %s read before: %w", record.GetRolloutId(), err)
	}
	if len(settled.Failing) > 0 {
		if _, err := transaction.Exec(ctx,
			`INSERT INTO agent_rollout_failing (rollout_id, agent_id) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING`,
			record.GetRolloutId(), settled.Failing); err != nil {
			return false, fmt.Errorf("record the failures rollout %s read: %w", record.GetRolloutId(), err)
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit the settling of rollout %s: %w", record.GetRolloutId(), err)
	}
	return true, nil
}

// The newest catalog, as it is served, or nothing while none was published.
func (r *AgentRollouts) Catalog(ctx context.Context) ([]byte, error) {
	var served []byte
	err := r.store.pool.QueryRow(ctx, "SELECT envelope FROM agent_update_catalogs ORDER BY version DESC LIMIT 1").Scan(&served)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the newest update catalog: %w", err)
	}
	return served, nil
}

func restoringRollout(row pgx.CollectableRow) (agentupdate.Held, error) {
	return scanRollout(row)
}

func scanRollout(row pgx.CollectableRow, more ...any) (agentupdate.Held, error) {
	var (
		id, tenant, version, note, state, createdBy, changedBy, reason string
		failures, agents, wave                                         int32
		waves, progress                                                []byte
		openedAt, createdAt, changedAt                                 time.Time
		held                                                           agentupdate.Held
	)
	targets := append([]any{&id, &tenant, &version, &failures, &note, &waves, &agents, &state, &wave, &openedAt,
		&held.Changes, &createdBy, &createdAt, &changedBy, &changedAt, &reason, &progress}, more...)
	if err := row.Scan(targets...); err != nil {
		return agentupdate.Held{}, err
	}
	var opened updatev1.Rollout
	if err := proto.Unmarshal(waves, &opened); err != nil {
		return agentupdate.Held{}, fmt.Errorf("read the waves of rollout %s: %w", id, err)
	}
	parsed, known := agentupdate.ParseState(state)
	if !known {
		return agentupdate.Held{}, fmt.Errorf("rollout %s stands %q, which no build writes", id, state)
	}
	held.Record = &updatev1.RolloutRecord{
		RolloutId: id,
		Rollout: &updatev1.Rollout{
			TenantId: tenant, Version: version, Waves: opened.GetWaves(), Failures: uint32(failures), Note: note,
		},
		State:        parsed,
		Wave:         uint32(wave),
		WaveOpenedAt: timestamppb.New(openedAt.UTC()),
		CreatedBy:    createdBy,
		CreatedAt:    timestamppb.New(createdAt.UTC()),
		ChangedBy:    changedBy,
		ChangedAt:    timestamppb.New(changedAt.UTC()),
		Reason:       reason,
	}
	held.Named = agents > 0
	if progress != nil {
		var read updatev1.RolloutProgress
		if err := proto.Unmarshal(progress, &read); err != nil {
			return agentupdate.Held{}, fmt.Errorf("read the progress of rollout %s: %w", id, err)
		}
		held.Record.Progress = &read
	}
	return held, nil
}

func encodeRolloutCursor(tenant string, created time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(tenant + "/" + strconv.FormatInt(created.UnixMicro(), 10) + "/" + id))
}

func decodeRolloutCursor(token string) (string, time.Time, string, error) {
	payload, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", time.Time{}, "", agentupdate.ErrRolloutCursor
	}
	parts := strings.Split(string(payload), "/")
	if len(parts) != 3 || parts[0] == "" || !agentupdate.ValidRolloutID(parts[2]) {
		return "", time.Time{}, "", agentupdate.ErrRolloutCursor
	}
	micros, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", time.Time{}, "", agentupdate.ErrRolloutCursor
	}
	return parts[0], time.UnixMicro(micros).UTC(), parts[2], nil
}
