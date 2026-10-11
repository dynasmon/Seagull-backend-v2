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

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const (
	agentPoliciesTable      = "agent_policies"
	agentPolicyTargetsTable = "agent_policy_targets"
	unregisteredShown       = 16
)

const policyColumns = `tenant_id, revision, policy_id, digest_sha256, signed_by, targets,
	issued_at, expires_at, published_by, published_at, note`

const insertAgentPolicy = `INSERT INTO agent_policies
	(tenant_id, revision, policy_id, digest_sha256, signed_by, targets,
	 issued_at, expires_at, published_by, published_at, note, envelope)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

const insertAgentPolicyTargets = `INSERT INTO agent_policy_targets (tenant_id, revision, agent_id)
SELECT $1, $2, unnest($3::text[])`

const servedPolicy = `SELECT agents.state, served.revision, served.envelope, served.digest_sha256
FROM agents
LEFT JOIN LATERAL (
	SELECT policies.revision, policies.envelope, policies.digest_sha256
	FROM agent_policy_targets targets
	JOIN agent_policies policies
		ON policies.tenant_id = targets.tenant_id AND policies.revision = targets.revision
	WHERE targets.agent_id = agents.agent_id AND targets.tenant_id = agents.tenant_id
	ORDER BY targets.revision DESC
	LIMIT 1
) served ON true
WHERE agents.agent_id = $1`

type AgentPolicies struct {
	store *Store
}

func (s *Store) AgentPolicies() *AgentPolicies { return &AgentPolicies{store: s} }

// Under the tenant's lock, so two publications racing are ordered: the second
// is compared with the revision the first recorded, and a tenant's revisions
// increase in the order they were recorded rather than in the order they were
// checked. Every agent the policy names is read inside the same transaction.
func (p *AgentPolicies) Publish(ctx context.Context, accepted agentpolicy.Accepted) (*policyv1.PublishedPolicy, error) {
	record := accepted.Record
	tenant := record.GetTenantId()

	transaction, err := p.store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin publishing a policy into %s: %w", tenant, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	if _, err := transaction.Exec(ctx, holdKey, agentPoliciesTable, tenant); err != nil {
		return nil, fmt.Errorf("hold the policies of %s: %w", tenant, err)
	}
	var highest int64
	if err := transaction.QueryRow(ctx,
		"SELECT coalesce(max(revision), 0) FROM agent_policies WHERE tenant_id = $1", tenant,
	).Scan(&highest); err != nil {
		return nil, fmt.Errorf("read the highest policy revision of %s: %w", tenant, err)
	}
	if record.GetRevision() <= uint64(highest) {
		return nil, fmt.Errorf("%w: %s holds revision %d, and this policy is revision %d",
			agentpolicy.ErrStale, tenant, highest, record.GetRevision())
	}

	rows, err := transaction.Query(ctx,
		"SELECT agent_id FROM agents WHERE tenant_id = $1 AND agent_id = ANY($2)", tenant, accepted.Targets)
	if err != nil {
		return nil, fmt.Errorf("read the agents a policy names: %w", err)
	}
	registered, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("read the agents a policy names: %w", err)
	}
	if missing := unregistered(accepted.Targets, registered); len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", agentpolicy.ErrUnregistered, listed(missing))
	}

	if _, err := transaction.Exec(ctx, insertAgentPolicy,
		tenant, int64(record.GetRevision()), record.GetPolicyId(), record.GetDigestSha256(),
		record.GetSignedBy(), int32(record.GetTargets()),
		record.GetIssuedAt().AsTime().UTC(), record.GetExpiresAt().AsTime().UTC(),
		record.GetPublishedBy(), record.GetPublishedAt().AsTime().UTC(), record.GetNote(), accepted.Served,
	); err != nil {
		if duplicate(err) {
			return nil, fmt.Errorf("%w: %s already holds revision %d", agentpolicy.ErrStale, tenant, record.GetRevision())
		}
		return nil, fmt.Errorf("record revision %d of %s: %w", record.GetRevision(), tenant, err)
	}
	if _, err := transaction.Exec(ctx, insertAgentPolicyTargets, tenant, int64(record.GetRevision()), accepted.Targets); err != nil {
		return nil, fmt.Errorf("record the agents revision %d of %s names: %w", record.GetRevision(), tenant, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit revision %d of %s: %w", record.GetRevision(), tenant, err)
	}
	return record, nil
}

func unregistered(named, registered []string) []string {
	held := make(map[string]struct{}, len(registered))
	for _, id := range registered {
		held[id] = struct{}{}
	}
	var missing []string
	for _, id := range named {
		if _, found := held[id]; !found {
			missing = append(missing, id)
		}
	}
	return missing
}

func listed(missing []string) string {
	shown := missing[:min(len(missing), unregisteredShown)]
	written := strings.Join(shown, ", ")
	if len(missing) > len(shown) {
		written += fmt.Sprintf(" and %d more", len(missing)-len(shown))
	}
	return written
}

// The scope is a predicate on every read: tenants a caller names beyond the
// ones they hold answer nothing rather than widening it.
func (p *AgentPolicies) Page(ctx context.Context, asked *policyv1.Query, tenants []string) (*policyv1.Page, error) {
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
	if named := asked.GetAgentId(); named != "" {
		where = append(where, `EXISTS (SELECT 1 FROM agent_policy_targets targets
			WHERE targets.agent_id = `+place(named)+`
			AND targets.tenant_id = agent_policies.tenant_id AND targets.revision = agent_policies.revision)`)
	}
	if asked.GetCursor() != "" {
		tenant, revision, err := decodePolicyCursor(asked.GetCursor())
		if err != nil {
			return nil, err
		}
		after, below := place(tenant), place(revision)
		where = append(where, "(tenant_id > "+after+" OR (tenant_id = "+after+" AND revision < "+below+"))")
	}

	rows, err := p.store.pool.Query(ctx,
		"SELECT "+policyColumns+" FROM agent_policies WHERE "+strings.Join(where, " AND ")+
			" ORDER BY tenant_id, revision DESC LIMIT "+place(limit+1), arguments...)
	if err != nil {
		return nil, fmt.Errorf("list agent policies: %w", err)
	}
	found, err := pgx.CollectRows(rows, restoring(false))
	if err != nil {
		return nil, fmt.Errorf("list agent policies: %w", err)
	}

	page := &policyv1.Page{Policies: found}
	if len(found) > limit {
		page.Policies = found[:limit]
		last := page.Policies[limit-1]
		page.NextCursor = encodePolicyCursor(last.GetTenantId(), last.GetRevision())
	}
	return page, nil
}

func (p *AgentPolicies) Policy(ctx context.Context, tenant string, revision uint64, tenants []string) (*policyv1.PublishedPolicy, error) {
	if !slices.Contains(tenants, tenant) || revision == 0 || revision > uint64(1<<63-1) {
		return nil, agentpolicy.ErrUnknown
	}
	rows, err := p.store.pool.Query(ctx,
		"SELECT "+policyColumns+", envelope FROM agent_policies WHERE tenant_id = $1 AND revision = $2",
		tenant, int64(revision))
	if err != nil {
		return nil, fmt.Errorf("read revision %d of %s: %w", revision, tenant, err)
	}
	found, err := pgx.CollectRows(rows, restoring(true))
	if err != nil {
		return nil, fmt.Errorf("read revision %d of %s: %w", revision, tenant, err)
	}
	if len(found) == 0 {
		return nil, agentpolicy.ErrUnknown
	}
	return found[0], nil
}

// An agent asking for its policy is not a caller with a scope: the connection
// proved which agent it is, and the agent belongs to the one tenant it was
// registered in.
func (p *AgentPolicies) Served(ctx context.Context, agentID string) (agentpolicy.Served, error) {
	var (
		state    string
		revision *int64
		envelope []byte
		digest   *string
	)
	err := p.store.pool.QueryRow(ctx, servedPolicy, agentID).Scan(&state, &revision, &envelope, &digest)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return agentpolicy.Served{}, agent.ErrUnknown
	case err != nil:
		return agentpolicy.Served{}, fmt.Errorf("read the policy agent %s is handed: %w", agentID, err)
	}
	served := agentpolicy.Served{State: agent.State(state)}
	if revision != nil && digest != nil {
		served.Revision, served.Envelope, served.Digest = uint64(*revision), envelope, *digest
	}
	return served, nil
}

func restoring(withEnvelope bool) pgx.RowToFunc[*policyv1.PublishedPolicy] {
	return func(row pgx.CollectableRow) (*policyv1.PublishedPolicy, error) {
		var (
			record              policyv1.PublishedPolicy
			revision            int64
			targets             int32
			issuedAt, expiresAt time.Time
			publishedAt         time.Time
			envelope            []byte
		)
		into := []any{
			&record.TenantId, &revision, &record.PolicyId, &record.DigestSha256, &record.SignedBy, &targets,
			&issuedAt, &expiresAt, &record.PublishedBy, &publishedAt, &record.Note,
		}
		if withEnvelope {
			into = append(into, &envelope)
		}
		if err := row.Scan(into...); err != nil {
			return nil, err
		}
		record.Revision = uint64(revision)
		record.Targets = uint32(targets)
		record.IssuedAt = timestamppb.New(issuedAt.UTC())
		record.ExpiresAt = timestamppb.New(expiresAt.UTC())
		record.PublishedAt = timestamppb.New(publishedAt.UTC())
		if withEnvelope {
			var held policyv1.SignedPolicy
			if err := proto.Unmarshal(envelope, &held); err != nil {
				return nil, fmt.Errorf("the stored envelope of revision %d of %s is unreadable: %w", revision, record.GetTenantId(), err)
			}
			record.Policy = &held
		}
		return &record, nil
	}
}

func encodePolicyCursor(tenant string, revision uint64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(tenant + "/" + strconv.FormatUint(revision, 10)))
}

func decodePolicyCursor(token string) (string, int64, error) {
	payload, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", 0, agentpolicy.ErrCursor
	}
	tenant, written, found := strings.Cut(string(payload), "/")
	if !found || tenant == "" {
		return "", 0, agentpolicy.ErrCursor
	}
	revision, err := strconv.ParseInt(written, 10, 64)
	if err != nil || revision <= 0 {
		return "", 0, agentpolicy.ErrCursor
	}
	return tenant, revision, nil
}
