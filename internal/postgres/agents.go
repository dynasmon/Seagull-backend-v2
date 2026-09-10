package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

type Agents struct {
	store *Store
}

func (s *Store) Agents() *Agents { return &Agents{store: s} }

const agentColumns = `agent_id, schema_version, tenant_id, state,
	platform_os, platform_architecture, platform_hostname, agent_version,
	identity_subject, identity_serial, identity_fingerprint, identity_issued_at, identity_expires_at,
	registered_at, changed_by, changed_at, revision`

var insertAgent = `INSERT INTO agents (` + agentColumns + `)
VALUES (` + placeholdersFor(agentColumns) + `)`

const insertAgentTransition = `INSERT INTO agent_transitions
	(agent_id, revision, from_state, to_state, actor, at, note)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (agent_id, revision) DO NOTHING`

// Registering an agent and the first line of its trail are one transaction, so
// a registry row can never exist with nothing saying who created it.
func (a *Agents) Register(ctx context.Context, asked *agentv1.Registration, actor string, at time.Time) (*agentv1.Agent, error) {
	registered, line, err := agent.Register(asked, actor, at)
	if err != nil {
		return nil, err
	}

	transaction, err := a.store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin registering agent %s: %w", registered.GetAgentId(), err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	if _, err := transaction.Exec(ctx, insertAgent, storedAgent(registered)...); err != nil {
		if duplicate(err) {
			return nil, fmt.Errorf("%w: %s", agent.ErrRegistered, registered.GetAgentId())
		}
		return nil, fmt.Errorf("register agent %s: %w", registered.GetAgentId(), err)
	}
	if _, err := transaction.Exec(ctx, insertAgentTransition, agentTrail(line)...); err != nil {
		return nil, fmt.Errorf("record the registration of agent %s: %w", registered.GetAgentId(), err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit the registration of agent %s: %w", registered.GetAgentId(), err)
	}
	return registered, nil
}

// Everything the registry has decided and the admission log has not been told,
// oldest first, so a control plane that lost the backbone catches up in the
// order the decisions were made.
func (a *Agents) Outstanding(ctx context.Context, limit int) ([]*agentv1.Admission, error) {
	if limit <= 0 {
		limit = DefaultPageSize
	}
	rows, err := a.store.pool.Query(ctx,
		`SELECT agent_id, tenant_id, state, revision, changed_at
		 FROM agents WHERE published_revision < revision
		 ORDER BY changed_at LIMIT $1`, min(limit, MaxPageSize))
	if err != nil {
		return nil, fmt.Errorf("read the agents the data plane has not been told about: %w", err)
	}
	return pgx.CollectRows(rows, restoreAdmission)
}

func (a *Agents) Announced(ctx context.Context, agentID string, revision uint64) error {
	if _, err := a.store.pool.Exec(ctx,
		`UPDATE agents SET published_revision = $2
		 WHERE agent_id = $1 AND published_revision < $2`, agentID, int64(revision),
	); err != nil {
		return fmt.Errorf("record that agent %s was announced: %w", agentID, err)
	}
	return nil
}

func (a *Agents) Agent(ctx context.Context, id string, tenants []string) (*agentv1.Agent, error) {
	rows, err := a.store.pool.Query(ctx,
		"SELECT "+agentColumns+" FROM agents WHERE agent_id = $1 AND tenant_id = ANY($2)", id, tenants)
	if err != nil {
		return nil, fmt.Errorf("read agent %s: %w", id, err)
	}
	found, err := pgx.CollectRows(rows, restoreAgent)
	if err != nil {
		return nil, fmt.Errorf("read agent %s: %w", id, err)
	}
	if len(found) == 0 {
		return nil, agent.ErrUnknown
	}
	return found[0], nil
}

func (a *Agents) History(ctx context.Context, id string, tenants []string) (*agentv1.History, error) {
	if _, err := a.Agent(ctx, id, tenants); err != nil {
		return nil, err
	}

	rows, err := a.store.pool.Query(ctx,
		`SELECT agent_id, revision, from_state, to_state, actor, at, note
		 FROM agent_transitions WHERE agent_id = $1 ORDER BY revision`, id)
	if err != nil {
		return nil, fmt.Errorf("read the trail of agent %s: %w", id, err)
	}
	carried, err := pgx.CollectRows(rows, restoreAgentTransition)
	if err != nil {
		return nil, fmt.Errorf("read the trail of agent %s: %w", id, err)
	}
	return &agentv1.History{AgentId: id, Transitions: carried}, nil
}

// The scope is a predicate on every read and is never composed from the cursor,
// so a position lifted from another caller's page still answers within the
// tenants this caller holds.
func (a *Agents) Page(ctx context.Context, asked *agentv1.Query, tenants []string) (*agentv1.Page, error) {
	limit := int(asked.GetLimit())
	if limit <= 0 {
		limit = DefaultPageSize
	}
	limit = min(limit, MaxPageSize)

	where := []string{"tenant_id = ANY($1)"}
	arguments := []any{tenants}
	place := func(value any) string {
		arguments = append(arguments, value)
		return "$" + strconv.Itoa(len(arguments))
	}

	if start := asked.GetRange().GetStart(); start != nil {
		where = append(where, "registered_at >= "+place(start.AsTime().UTC()))
	}
	if end := asked.GetRange().GetEnd(); end != nil {
		where = append(where, "registered_at < "+place(end.AsTime().UTC()))
	}
	if named := agentStates(asked.GetStates()); len(named) > 0 {
		where = append(where, "state = ANY("+place(named)+")")
	}
	if asked.GetCursor() != "" {
		after, err := decodeAgentCursor(asked.GetCursor())
		if err != nil {
			return nil, err
		}
		where = append(where, "agent_id > "+place(after))
	}

	query := "SELECT " + agentColumns + " FROM agents WHERE " + strings.Join(where, " AND ") +
		" ORDER BY agent_id LIMIT " + place(limit+1)

	rows, err := a.store.pool.Query(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	found, err := pgx.CollectRows(rows, restoreAgent)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}

	page := &agentv1.Page{Agents: found}
	if len(found) > limit {
		page.Agents = found[:limit]
		page.NextCursor = encodeAgentCursor(page.Agents[limit-1].GetAgentId())
	}
	return page, nil
}

// Read, decide and write in one transaction with the row held, so the state the
// move was decided against is the state it is applied to. Without the lock two
// operators could each read `active` and both be allowed to revoke it.
func (a *Agents) Move(ctx context.Context, id string, tenants []string, asked agent.Move) (*agentv1.Agent, error) {
	return a.move(ctx, id, asked,
		"SELECT "+agentColumns+" FROM agents WHERE agent_id = $1 AND tenant_id = ANY($2) FOR UPDATE",
		[]any{id, tenants})
}

// An agent renewing its own certificate is not a caller with a scope: the
// connection proved which agent it is, and an agent belongs to one tenant it did
// not choose. Whether the platform still signs for it is decided by agent.Apply
// under the held row.
func (a *Agents) Renew(ctx context.Context, id string, asked agent.Move) (*agentv1.Agent, error) {
	asked.Renewal = true
	return a.move(ctx, id, asked,
		"SELECT "+agentColumns+" FROM agents WHERE agent_id = $1 FOR UPDATE", []any{id})
}

func (a *Agents) move(ctx context.Context, id string, asked agent.Move, query string, arguments []any) (*agentv1.Agent, error) {
	transaction, err := a.store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin moving agent %s: %w", id, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	rows, err := transaction.Query(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("read agent %s: %w", id, err)
	}
	held, err := pgx.CollectRows(rows, restoreAgent)
	if err != nil {
		return nil, fmt.Errorf("read agent %s: %w", id, err)
	}
	if len(held) == 0 {
		return nil, agent.ErrUnknown
	}

	moved, line, err := agent.Apply(held[0], asked)
	if err != nil {
		return nil, err
	}

	if _, err := transaction.Exec(ctx,
		`UPDATE agents SET state = $2, changed_by = $3, changed_at = $4, revision = $5,
			identity_subject = $6, identity_serial = $7, identity_fingerprint = $8,
			identity_issued_at = $9, identity_expires_at = $10
		 WHERE agent_id = $1`,
		moved.GetAgentId(),
		agentState(moved.GetState()), moved.GetChangedBy(), moved.GetChangedAt().AsTime(), int64(moved.GetRevision()),
		moved.GetIdentity().GetSubject(), moved.GetIdentity().GetSerial(), moved.GetIdentity().GetFingerprintSha256(),
		optional(moved.GetIdentity().GetIssuedAt()), optional(moved.GetIdentity().GetExpiresAt()),
	); err != nil {
		if duplicate(err) {
			return nil, fmt.Errorf("%w: that certificate is bound to another agent", agent.ErrMalformedIdentity)
		}
		return nil, fmt.Errorf("move agent %s: %w", id, err)
	}
	if _, err := transaction.Exec(ctx, insertAgentTransition, agentTrail(line)...); err != nil {
		return nil, fmt.Errorf("record the move of agent %s: %w", id, err)
	}
	if signed := agent.Certificate(moved, asked); signed != nil {
		if err := recordCertificate(ctx, transaction, signed, asked.At); err != nil {
			return nil, err
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit the move of agent %s: %w", id, err)
	}
	return moved, nil
}

func storedAgent(one *agentv1.Agent) []any {
	return []any{
		one.GetAgentId(), int32(one.GetSchemaVersion()), one.GetTenantId(), agentState(one.GetState()),
		one.GetPlatform().GetOs(), one.GetPlatform().GetArchitecture(), one.GetPlatform().GetHostname(),
		one.GetAgentVersion(),
		one.GetIdentity().GetSubject(), one.GetIdentity().GetSerial(), one.GetIdentity().GetFingerprintSha256(),
		optional(one.GetIdentity().GetIssuedAt()), optional(one.GetIdentity().GetExpiresAt()),
		one.GetRegisteredAt().AsTime(), one.GetChangedBy(), one.GetChangedAt().AsTime(), int64(one.GetRevision()),
	}
}

func agentTrail(line *agentv1.Transition) []any {
	return []any{
		line.GetAgentId(), int64(line.GetRevision()),
		agentState(line.GetFrom()), agentState(line.GetTo()),
		line.GetActor(), line.GetAt().AsTime(), line.GetNote(),
	}
}

func restoreAgent(row pgx.CollectableRow) (*agentv1.Agent, error) {
	var (
		one                            agentv1.Agent
		schemaVersion                  int32
		named                          string
		os, architecture, hostname     string
		subject, serial, fingerprintOf string
		issuedAt, expiresAt            *time.Time
		registeredAt, changedAt        time.Time
		revision                       int64
	)

	if err := row.Scan(
		&one.AgentId, &schemaVersion, &one.TenantId, &named,
		&os, &architecture, &hostname, &one.AgentVersion,
		&subject, &serial, &fingerprintOf, &issuedAt, &expiresAt,
		&registeredAt, &one.ChangedBy, &changedAt, &revision,
	); err != nil {
		return nil, err
	}

	one.SchemaVersion = uint32(schemaVersion)
	one.State = agent.State(named).Wire()
	if os != "" || architecture != "" || hostname != "" {
		one.Platform = &agentv1.Platform{Os: os, Architecture: architecture, Hostname: hostname}
	}
	if subject != "" || serial != "" || fingerprintOf != "" {
		one.Identity = &agentv1.Identity{
			Subject:           subject,
			Serial:            serial,
			FingerprintSha256: fingerprintOf,
			IssuedAt:          instant(issuedAt),
			ExpiresAt:         instant(expiresAt),
		}
	}
	one.RegisteredAt = timestamppb.New(registeredAt.UTC())
	one.ChangedAt = timestamppb.New(changedAt.UTC())
	one.Revision = uint64(revision)
	return &one, nil
}

func restoreAdmission(row pgx.CollectableRow) (*agentv1.Admission, error) {
	var (
		record    agentv1.Admission
		named     string
		revision  int64
		changedAt time.Time
	)
	if err := row.Scan(&record.AgentId, &record.TenantId, &named, &revision, &changedAt); err != nil {
		return nil, err
	}
	record.State = agent.State(named).Wire()
	record.Revision = uint64(revision)
	record.ChangedAt = timestamppb.New(changedAt.UTC())
	return &record, nil
}

func restoreAgentTransition(row pgx.CollectableRow) (*agentv1.Transition, error) {
	var (
		line     agentv1.Transition
		revision int64
		from, to string
		at       time.Time
	)
	if err := row.Scan(&line.AgentId, &revision, &from, &to, &line.Actor, &at, &line.Note); err != nil {
		return nil, err
	}
	line.Revision = uint64(revision)
	line.From = agent.State(from).Wire()
	line.To = agent.State(to).Wire()
	line.At = timestamppb.New(at.UTC())
	return &line, nil
}

func agentState(value agentv1.State) string {
	named, known := agent.FromWire(value)
	if !known {
		return ""
	}
	return named.String()
}

func agentStates(asked []agentv1.State) []string {
	named := make([]string, 0, len(asked))
	for _, one := range asked {
		if written := agentState(one); written != "" {
			named = append(named, written)
		}
	}
	return named
}

func duplicate(err error) bool {
	var refusal *pgconn.PgError
	return errors.As(err, &refusal) && refusal.Code == "23505"
}

func encodeAgentCursor(id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(id))
}

func decodeAgentCursor(token string) (string, error) {
	payload, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(payload) == 0 {
		return "", agent.ErrCursor
	}
	return string(payload), nil
}
