package postgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/disposition"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

const (
	dispositionsTable = "vulnerability_dispositions"
	withdrawalsTable  = "vulnerability_disposition_withdrawals"
)

const readDispositions = `SELECT held.disposition_id, held.schema_version, held.tenant_id, held.vulnerability_id,
	held.agent_id, held.package_name, held.kind, held.reason, held.actor, held.decided_at, held.expires_at,
	ended.withdrawn_by, ended.withdrawn_at, ended.reason
FROM vulnerability_dispositions held
LEFT JOIN vulnerability_disposition_withdrawals ended ON ended.disposition_id = held.disposition_id`

// The agent is looked up by the statement that records the disposition, so
// one naming an agent its tenant never registered is not kept at all.
const insertDisposition = `INSERT INTO vulnerability_dispositions
	(disposition_id, schema_version, tenant_id, vulnerability_id, agent_id, package_name,
	 kind, reason, actor, decided_at, expires_at)
SELECT $1::text, $2::integer, $3::text, $4::text, $5::text, $6::text,
	$7::text, $8::text, $9::text, $10::timestamptz, $11::timestamptz
WHERE $5::text = '' OR EXISTS (SELECT 1 FROM agents WHERE agents.agent_id = $5::text AND agents.tenant_id = $3::text)`

const insertWithdrawal = `INSERT INTO vulnerability_disposition_withdrawals (disposition_id, withdrawn_by, withdrawn_at, reason)
VALUES ($1, $2, $3, $4)
ON CONFLICT (disposition_id) DO NOTHING`

// Both tables are written by INSERT alone: what a person decided, and its
// ending, are facts added beside each other and never edited or removed.
type Dispositions struct {
	store *Store
}

func (s *Store) Dispositions() *Dispositions { return &Dispositions{store: s} }

func (d *Dispositions) Record(ctx context.Context, recorded *vulnerabilityv1.Disposition) error {
	kind, known := disposition.KindOf(recorded.GetKind())
	if !known {
		return fmt.Errorf("%w: %s is not a kind of disposition", disposition.ErrMalformed, recorded.GetKind())
	}
	tag, err := d.store.pool.Exec(ctx, insertDisposition,
		recorded.GetDispositionId(), int32(recorded.GetSchemaVersion()), recorded.GetTenantId(),
		recorded.GetVulnerabilityId(), recorded.GetAgentId(), recorded.GetPackageName(),
		kind.String(), recorded.GetReason(), recorded.GetActor(),
		recorded.GetDecidedAt().AsTime().UTC(), recorded.GetExpiresAt().AsTime().UTC(),
	)
	if err != nil {
		return fmt.Errorf("record disposition %s: %w", recorded.GetDispositionId(), err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s is not registered in %s", disposition.ErrUnregistered, recorded.GetAgentId(), recorded.GetTenantId())
	}
	return nil
}

// Decided against the disposition as it was read and settled by the key: a
// withdrawal that lost a race to another is told the disposition lapsed.
func (d *Dispositions) Withdraw(ctx context.Context, id string, tenants []string, withdrawal disposition.Withdrawal) (*vulnerabilityv1.Disposition, error) {
	if !disposition.ValidID(id) {
		return nil, disposition.ErrUnknown
	}
	rows, err := d.store.pool.Query(ctx, readDispositions+" WHERE held.disposition_id = $1 AND held.tenant_id = ANY($2)", id, tenants)
	if err != nil {
		return nil, fmt.Errorf("read disposition %s: %w", id, err)
	}
	held, err := pgx.CollectRows(rows, restoreDisposition)
	if err != nil {
		return nil, fmt.Errorf("read disposition %s: %w", id, err)
	}
	if len(held) == 0 {
		return nil, disposition.ErrUnknown
	}

	withdrawn, err := disposition.Withdraw(held[0], withdrawal)
	if err != nil {
		return nil, err
	}
	tag, err := d.store.pool.Exec(ctx, insertWithdrawal,
		id, withdrawn.GetWithdrawnBy(), withdrawn.GetWithdrawnAt().AsTime().UTC(), withdrawn.GetWithdrawalReason())
	if err != nil {
		return nil, fmt.Errorf("record the withdrawal of disposition %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("%w: %s was withdrawn by another request", disposition.ErrLapsed, id)
	}
	return withdrawn, nil
}

// The tenants are a predicate on every read and never come from the cursor.
// An agent is answered with every disposition covering it: its own, and those
// of its tenant that name no agent.
func (d *Dispositions) Page(ctx context.Context, asked *vulnerabilityv1.DispositionQuery, tenants []string, at time.Time) (*vulnerabilityv1.DispositionPage, error) {
	limit := int(asked.GetLimit())
	if limit <= 0 {
		limit = DefaultPageSize
	}
	limit = min(limit, MaxPageSize)

	where := []string{"held.tenant_id = ANY($1)"}
	arguments := []any{tenants}
	place := func(value any) string {
		arguments = append(arguments, value)
		return "$" + strconv.Itoa(len(arguments))
	}
	if named := asked.GetVulnerabilityIds(); len(named) > 0 {
		where = append(where, "held.vulnerability_id = ANY("+place(named)+")")
	}
	if named := asked.GetAgentIds(); len(named) > 0 {
		where = append(where, "(held.agent_id = '' OR held.agent_id = ANY("+place(named)+"))")
	}
	if named := kinds(asked.GetKinds()); len(named) > 0 {
		where = append(where, "held.kind = ANY("+place(named)+")")
	}
	if !asked.GetLapsed() {
		where = append(where, "ended.disposition_id IS NULL AND held.expires_at > "+place(at.UTC()))
	}
	if asked.GetCursor() != "" {
		decided, id, err := decodeDispositionCursor(asked.GetCursor())
		if err != nil {
			return nil, err
		}
		where = append(where, "(held.decided_at, held.disposition_id) < ("+place(decided)+", "+place(id)+")")
	}

	rows, err := d.store.pool.Query(ctx, readDispositions+" WHERE "+strings.Join(where, " AND ")+
		" ORDER BY held.decided_at DESC, held.disposition_id DESC LIMIT "+place(limit+1), arguments...)
	if err != nil {
		return nil, fmt.Errorf("list dispositions: %w", err)
	}
	found, err := pgx.CollectRows(rows, restoreDisposition)
	if err != nil {
		return nil, fmt.Errorf("list dispositions: %w", err)
	}

	page := &vulnerabilityv1.DispositionPage{Dispositions: found}
	if len(found) > limit {
		page.Dispositions = found[:limit]
		last := page.Dispositions[limit-1]
		page.NextCursor = encodeDispositionCursor(last.GetDecidedAt().AsTime(), last.GetDispositionId())
	}
	return page, nil
}

func kinds(asked []vulnerabilityv1.DispositionKind) []string {
	named := make([]string, 0, len(asked))
	for _, one := range asked {
		if kind, known := disposition.KindOf(one); known {
			named = append(named, kind.String())
		}
	}
	return named
}

func restoreDisposition(row pgx.CollectableRow) (*vulnerabilityv1.Disposition, error) {
	var (
		one                  vulnerabilityv1.Disposition
		schemaVersion        int32
		kind                 string
		decidedAt, expiresAt time.Time
		withdrawnBy, reason  *string
		withdrawnAt          *time.Time
	)
	if err := row.Scan(
		&one.DispositionId, &schemaVersion, &one.TenantId, &one.VulnerabilityId,
		&one.AgentId, &one.PackageName, &kind, &one.Reason, &one.Actor, &decidedAt, &expiresAt,
		&withdrawnBy, &withdrawnAt, &reason,
	); err != nil {
		return nil, err
	}
	one.SchemaVersion = uint32(schemaVersion)
	one.Kind = disposition.Kind(kind).Wire()
	one.DecidedAt = timestamppb.New(decidedAt.UTC())
	one.ExpiresAt = timestamppb.New(expiresAt.UTC())
	if withdrawnAt != nil && withdrawnBy != nil && reason != nil {
		one.WithdrawnBy = *withdrawnBy
		one.WithdrawnAt = timestamppb.New(withdrawnAt.UTC())
		one.WithdrawalReason = *reason
	}
	return &one, nil
}

func encodeDispositionCursor(decided time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(decided.UnixMicro(), 10) + "/" + id))
}

func decodeDispositionCursor(token string) (time.Time, string, error) {
	payload, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return time.Time{}, "", disposition.ErrCursor
	}
	written, id, found := strings.Cut(string(payload), "/")
	if !found || !disposition.ValidID(id) {
		return time.Time{}, "", disposition.ErrCursor
	}
	micros, err := strconv.ParseInt(written, 10, 64)
	if err != nil {
		return time.Time{}, "", disposition.ErrCursor
	}
	return time.UnixMicro(micros).UTC(), id, nil
}
