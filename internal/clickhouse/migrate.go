package clickhouse

import (
	"context"
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const ledger = "schema_migrations"

// The record of what has been applied cannot itself be one of the things waiting
// to be applied, so the migrator creates it.
const createLedger = `CREATE TABLE IF NOT EXISTS ` + ledger + `
(
    version    UInt32,
    name       String,
    applied_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY version`

type Migrator struct {
	connection driver.Conn
}

func NewMigrator(configuration Config) (*Migrator, error) {
	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}
	return &Migrator{connection: connection}, nil
}

// Applied in order and recorded one at a time, so an interrupted run resumes
// where it stopped — safe only because every statement is idempotent.
func (m *Migrator) Apply(ctx context.Context) ([]string, error) {
	if err := m.connection.Exec(ctx, createLedger); err != nil {
		return nil, fmt.Errorf("create %s: %w", ledger, err)
	}

	outstanding, err := pending(ctx, m.connection)
	if err != nil {
		return nil, err
	}

	applied := make([]string, 0, len(outstanding))
	for _, entry := range outstanding {
		for _, statement := range entry.statements {
			if err := m.connection.Exec(ctx, statement); err != nil {
				return applied, fmt.Errorf("apply %s: %w", entry, err)
			}
		}
		if err := m.connection.Exec(ctx,
			"INSERT INTO "+ledger+" (version, name) VALUES (?, ?)",
			uint32(entry.version), entry.name,
		); err != nil {
			return applied, fmt.Errorf("record %s as applied: %w", entry, err)
		}
		applied = append(applied, entry.String())
	}
	return applied, nil
}

func (m *Migrator) Ping(ctx context.Context) error {
	if err := m.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the event store: %w", err)
	}
	return nil
}

func (m *Migrator) Close() error { return m.connection.Close() }

// A store that was never migrated has no ledger, so the message says so rather
// than reading as a broken database.
func pending(ctx context.Context, connection driver.Conn) ([]migration, error) {
	rows, err := connection.Query(ctx, "SELECT version FROM "+ledger)
	if err != nil {
		return nil, fmt.Errorf("read %s, which a migrated store always has: %w", ledger, err)
	}
	defer func() { _ = rows.Close() }()

	recorded := map[uint64]struct{}{}
	for rows.Next() {
		var version uint32
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("read %s: %w", ledger, err)
		}
		recorded[uint64(version)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", ledger, err)
	}

	var outstanding []migration
	for _, candidate := range migrations {
		if _, done := recorded[candidate.version]; !done {
			outstanding = append(outstanding, candidate)
		}
	}
	return outstanding, nil
}
