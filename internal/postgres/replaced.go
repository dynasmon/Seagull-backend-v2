package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const (
	endReplaced = `UPDATE agent_replaced_certificates
	SET closure = $2, closed_at = GREATEST(opened_at, $3), decided_at = GREATEST(decided_at, $3), revision = revision + 1
	WHERE agent_id = $1 AND closed_at IS NULL AND in_force <> $4`

	observeReplaced = `INSERT INTO agent_replaced_certificates
		(agent_id, in_force, opened_at, last_observed_at, observations, decided_at, revision, use_route)
	VALUES ($1, $2, $3, $3, 1, $3, 1, $4)
	ON CONFLICT (agent_id, in_force) DO UPDATE SET
		last_observed_at = GREATEST(agent_replaced_certificates.last_observed_at, EXCLUDED.last_observed_at),
		observations     = agent_replaced_certificates.observations + 1,
		closure          = '',
		closed_at        = NULL,
		decided_at       = GREATEST(agent_replaced_certificates.decided_at, EXCLUDED.decided_at),
		revision         = agent_replaced_certificates.revision + 1,
		use_route        = CASE WHEN EXCLUDED.last_observed_at >= agent_replaced_certificates.last_observed_at
		                        THEN EXCLUDED.use_route ELSE agent_replaced_certificates.use_route END`
)

// Asked before a renewal is signed, under the row lock binding would take, so a
// renewal the registry refuses spends no signature (INT-12). A refusal as
// already replaced is recorded in the transaction that decided it; nothing else
// is written, since nothing was bound.
func (a *Agents) Renewable(ctx context.Context, id string, asked agent.Move) error {
	asked.Renewal = true
	transaction, err := a.store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin asking whether agent %s renews: %w", id, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	rows, err := transaction.Query(ctx, "SELECT "+agentColumns+" FROM agents WHERE agent_id = $1 FOR UPDATE", id)
	if err != nil {
		return fmt.Errorf("read agent %s: %w", id, err)
	}
	held, err := pgx.CollectRows(rows, restoreAgent)
	if err != nil {
		return fmt.Errorf("read agent %s: %w", id, err)
	}
	if len(held) == 0 {
		return agent.ErrUnknown
	}
	if asked.Bound, err = boundAnswer(ctx, transaction, id); err != nil {
		return err
	}
	refused := agent.Renewing(held[0], asked)
	if !errors.Is(refused, agent.ErrCertificateReplaced) {
		return refused
	}
	if err := replacedCommitted(ctx, transaction, held[0], asked.At, ""); err != nil {
		return err
	}
	return refused
}

// A certificate the agent listener refused on a route other than renewal, as
// not the one in force, recorded as a refused renewal is: under the agent's row
// lock, in the episode of the certificate in force. A refusal decided under a
// binding that has since moved, or of an agent no longer admitted, records
// nothing, since the episode it would belong to is over.
func (a *Agents) ReplacedUsed(ctx context.Context, id, inForce, route string, at time.Time) error {
	transaction, err := a.store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin recording the replaced certificate agent %s presented: %w", id, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	rows, err := transaction.Query(ctx, "SELECT "+agentColumns+" FROM agents WHERE agent_id = $1 FOR UPDATE", id)
	if err != nil {
		return fmt.Errorf("read agent %s: %w", id, err)
	}
	held, err := pgx.CollectRows(rows, restoreAgent)
	switch {
	case err != nil:
		return fmt.Errorf("read agent %s: %w", id, err)
	case len(held) == 0:
		return agent.ErrUnknown
	}
	state, known := agent.FromWire(held[0].GetState())
	if !known || !state.Admits() || held[0].GetIdentity().GetFingerprintSha256() != inForce || inForce == "" {
		return nil
	}
	return replacedCommitted(ctx, transaction, held[0], at, route)
}

func replacedCommitted(ctx context.Context, transaction pgx.Tx, current *agentv1.Agent, at time.Time, route string) error {
	inForce := current.GetIdentity().GetFingerprintSha256()
	if _, err := transaction.Exec(ctx, endReplaced, current.GetAgentId(), agentfinding.ClosureName(agentv1.Finding_CLOSURE_REBOUND), at.UTC(), inForce); err != nil {
		return fmt.Errorf("end the replaced certificates of agent %s: %w", current.GetAgentId(), err)
	}
	if _, err := transaction.Exec(ctx, observeReplaced, current.GetAgentId(), inForce, at.UTC(), route); err != nil {
		return fmt.Errorf("record the replaced certificate agent %s presented: %w", current.GetAgentId(), err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit the replaced certificate agent %s presented: %w", current.GetAgentId(), err)
	}
	return nil
}

func replacedEnded(ctx context.Context, transaction pgx.Tx, before, after *agentv1.Agent, at time.Time) error {
	closure := agentfinding.Ends(before, after)
	if closure == agentv1.Finding_CLOSURE_UNSPECIFIED {
		return nil
	}
	if _, err := transaction.Exec(ctx, endReplaced, after.GetAgentId(), agentfinding.ClosureName(closure), at.UTC(), ""); err != nil {
		return fmt.Errorf("end the replaced certificates of agent %s: %w", after.GetAgentId(), err)
	}
	return nil
}

// Every decision the findings log has not been told, oldest first.
func (a *Agents) Unpublished(ctx context.Context, limit int) ([]agentfinding.Replaced, error) {
	if limit <= 0 {
		limit = DefaultPageSize
	}
	rows, err := a.store.pool.Query(ctx,
		`SELECT r.agent_id, a.tenant_id, r.in_force, r.opened_at, r.last_observed_at, r.observations,
			r.closure, r.closed_at, r.decided_at, r.revision, r.use_route
		 FROM agent_replaced_certificates r JOIN agents a ON a.agent_id = r.agent_id
		 WHERE r.published_revision < r.revision
		 ORDER BY r.decided_at, r.agent_id LIMIT $1`, min(limit, MaxPageSize))
	if err != nil {
		return nil, fmt.Errorf("read the replaced certificates the findings log has not been told about: %w", err)
	}
	return pgx.CollectRows(rows, restoreReplaced)
}

func (a *Agents) Published(ctx context.Context, used agentfinding.Replaced) error {
	if _, err := a.store.pool.Exec(ctx,
		`UPDATE agent_replaced_certificates SET published_revision = $3
		 WHERE agent_id = $1 AND in_force = $2 AND published_revision < $3`,
		used.AgentID, used.InForce, int64(used.Revision),
	); err != nil {
		return fmt.Errorf("record that the replaced certificate of agent %s was published: %w", used.AgentID, err)
	}
	return nil
}

func (a *Agents) DecideAgain(ctx context.Context, before, now time.Time) error {
	if _, err := a.store.pool.Exec(ctx,
		`UPDATE agent_replaced_certificates SET decided_at = $2, revision = revision + 1
		 WHERE closed_at IS NULL AND decided_at < $1`, before.UTC(), now.UTC(),
	); err != nil {
		return fmt.Errorf("decide again the replaced certificates still open: %w", err)
	}
	return nil
}

func restoreReplaced(row pgx.CollectableRow) (agentfinding.Replaced, error) {
	var (
		used     agentfinding.Replaced
		closure  string
		closedAt *time.Time
		count    int64
		revision int64
	)
	if err := row.Scan(&used.AgentID, &used.TenantID, &used.InForce, &used.OpenedAt, &used.LastObservedAt, &count,
		&closure, &closedAt, &used.DecidedAt, &revision, &used.Route); err != nil {
		return agentfinding.Replaced{}, err
	}
	used.Observations, used.Revision = uint64(count), uint64(revision)
	if closure != "" {
		named, declared := agentv1.Finding_Closure_value["CLOSURE_"+strings.ToUpper(closure)]
		if !declared || closedAt == nil {
			return agentfinding.Replaced{}, fmt.Errorf("the replaced certificate of agent %s ended as %q, which no finding says", used.AgentID, closure)
		}
		used.Closure, used.ClosedAt = agentv1.Finding_Closure(named), closedAt.UTC()
	}
	used.OpenedAt, used.LastObservedAt, used.DecidedAt = used.OpenedAt.UTC(), used.LastObservedAt.UTC(), used.DecidedAt.UTC()
	return used, nil
}
