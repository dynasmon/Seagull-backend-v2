package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const ledger = "schema_migrations"

const createLedger = `CREATE TABLE IF NOT EXISTS ` + ledger + `
(
    version    BIGINT      PRIMARY KEY,
    name       TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

type Migrator struct {
	pool *pgxpool.Pool
}

func NewMigrator(ctx context.Context, configuration Config) (*Migrator, error) {
	pool, err := connect(ctx, configuration)
	if err != nil {
		return nil, err
	}
	return &Migrator{pool: pool}, nil
}

// Each migration and the ledger row recording it are one transaction, so an
// interrupted run leaves the schema either before it or after it and never
// half-way through: PostgreSQL rolls DDL back, which is what lets the statements
// be ordinary rather than individually idempotent.
func (m *Migrator) Apply(ctx context.Context) ([]string, error) {
	if _, err := m.pool.Exec(ctx, createLedger); err != nil {
		return nil, fmt.Errorf("create %s: %w", ledger, err)
	}

	outstanding, err := m.pending(ctx)
	if err != nil {
		return nil, err
	}

	applied := make([]string, 0, len(outstanding))
	for _, entry := range outstanding {
		if err := m.apply(ctx, entry); err != nil {
			return applied, err
		}
		applied = append(applied, entry.String())
	}
	return applied, nil
}

func (m *Migrator) apply(ctx context.Context, entry migration) error {
	transaction, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin %s: %w", entry, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	if _, err := transaction.Exec(ctx, entry.body); err != nil {
		return fmt.Errorf("apply %s: %w", entry, err)
	}
	if _, err := transaction.Exec(ctx,
		"INSERT INTO "+ledger+" (version, name) VALUES ($1, $2)", entry.version, entry.name,
	); err != nil {
		return fmt.Errorf("record %s as applied: %w", entry, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit %s: %w", entry, err)
	}
	return nil
}

func (m *Migrator) pending(ctx context.Context) ([]migration, error) {
	rows, err := m.pool.Query(ctx, "SELECT version FROM "+ledger)
	if err != nil {
		return nil, fmt.Errorf("read %s, which a migrated store always has: %w", ledger, err)
	}
	recorded, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", ledger, err)
	}

	done := map[uint64]struct{}{}
	for _, version := range recorded {
		done[uint64(version)] = struct{}{}
	}

	var outstanding []migration
	for _, candidate := range migrations {
		if _, already := done[candidate.version]; !already {
			outstanding = append(outstanding, candidate)
		}
	}
	return outstanding, nil
}

func (m *Migrator) Ping(ctx context.Context) error {
	if err := m.pool.Ping(ctx); err != nil {
		return fmt.Errorf("reach the alert store: %w", err)
	}
	return nil
}

func (m *Migrator) Close() error {
	m.pool.Close()
	return nil
}
