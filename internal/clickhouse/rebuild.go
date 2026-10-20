package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
)

const (
	unknownTable    = 60
	noTableToAttach = 390
)

// A sorting key cannot change in place, so a migration declared here creates the
// table as it is to be ordered under a name of its own. The migrator copies the
// live table into it while writers keep writing, exchanges the two names, and
// copies again whatever reached the old table after the first copy began.
var rebuilds = map[uint64]rebuild{}

type rebuild struct {
	table   string
	staging string
}

// A rebuild resumes from what the store holds rather than from what the
// migration remembers, so its migration holds nothing but the table it creates.
func (r rebuild) check(entry migration) error {
	if len(entry.statements) != 1 {
		return fmt.Errorf("a rebuild of %s is the one statement creating %s, and %s has %d",
			r.table, r.staging, entry, len(entry.statements))
	}
	if _, creates := createTableBody(entry.statements[0], r.staging); !creates {
		return fmt.Errorf("a rebuild of %s creates %s, which %s does not", r.table, r.staging, entry)
	}
	if _, err := declaredSortingKey(entry.statements[0]); err != nil {
		return fmt.Errorf("%s: %w", r.staging, err)
	}
	return nil
}

func (m *Migrator) rebuild(ctx context.Context, entry migration) error {
	plan := *entry.rebuild
	target, err := declaredSortingKey(entry.statements[0])
	if err != nil {
		return err
	}
	columns, err := declaredColumnsIn([]migration{entry}, plan.staging)
	if err != nil {
		return err
	}
	current, found, err := m.sortingKey(ctx, plan.table)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s does not exist to be rebuilt", plan.table)
	}

	var copiedThrough uint64
	if !sameKey(current, target) {
		m.logger.Info("table_rebuild_started",
			slog.String("table", plan.table), slog.String("sorting_key", target))
		if copiedThrough, err = m.copyLive(ctx, entry, plan, target, columns); err != nil {
			return err
		}
		if err := m.connection.Exec(ctx, "EXCHANGE TABLES "+plan.table+" AND "+plan.staging); err != nil {
			return fmt.Errorf("exchange %s and %s: %w", plan.table, plan.staging, err)
		}
		m.logger.Info("table_rebuild_exchanged", slog.String("table", plan.table))
	}
	return m.settle(ctx, plan, target, columns, copiedThrough)
}

func (m *Migrator) copyLive(ctx context.Context, entry migration, plan rebuild, target string, columns []string) (uint64, error) {
	if err := m.connection.Exec(ctx, entry.statements[0]); err != nil {
		return 0, fmt.Errorf("create %s: %w", plan.staging, err)
	}
	staged, found, err := m.sortingKey(ctx, plan.staging)
	if err != nil {
		return 0, err
	}
	if !found || !sameKey(staged, target) {
		return 0, fmt.Errorf("%s is ordered by %q rather than %q: decide what it holds before %s is rebuilt",
			plan.staging, staged, target, plan.table)
	}

	var through uint64
	if err := m.connection.QueryRow(ctx,
		"SELECT toUInt64(max(max_block_number)) FROM system.parts WHERE database = currentDatabase() AND table = ? AND active",
		plan.table).Scan(&through); err != nil {
		return 0, fmt.Errorf("read the newest block of %s: %w", plan.table, err)
	}
	partitions, err := m.partitions(ctx, plan.table)
	if err != nil {
		return 0, err
	}

	listed := strings.Join(columns, ", ")
	for _, partition := range partitions {
		if err := m.connection.Exec(ctx, "INSERT INTO "+plan.staging+" ("+listed+") SELECT "+listed+
			" FROM "+plan.table+" WHERE _partition_id = ?", partition); err != nil {
			return 0, fmt.Errorf("copy partition %s of %s: %w", partition, plan.table, err)
		}
		m.logger.Info("table_rebuild_partition_copied",
			slog.String("table", plan.table), slog.String("partition", partition))
	}
	return through, nil
}

// A write that resolved the old table before the exchange holds it until it
// ends, and a synchronous detach waits for every such write, so the copy made
// after it holds everything the old table will ever hold. A part merged since the
// first copy is named after the newest block in it and is copied whole.
func (m *Migrator) settle(ctx context.Context, plan rebuild, target string, columns []string, copiedThrough uint64) error {
	displaced, found, err := m.sortingKey(ctx, plan.staging)
	if err != nil {
		return err
	}
	if !found {
		reattached, err := m.reattach(ctx, plan.staging)
		if err != nil || !reattached {
			return err
		}
		if displaced, _, err = m.sortingKey(ctx, plan.staging); err != nil {
			return err
		}
	}
	if sameKey(displaced, target) {
		return fmt.Errorf("%s is already ordered by %q and %s, ordered the same way, still exists: decide what it holds before migrating again",
			plan.table, target, plan.staging)
	}

	if err := m.connection.Exec(ctx, "DETACH TABLE "+plan.staging+" SYNC"); err != nil {
		return fmt.Errorf("wait for the writes on their way to %s: %w", plan.staging, err)
	}
	if err := m.connection.Exec(ctx, "ATTACH TABLE "+plan.staging); err != nil {
		return fmt.Errorf("attach %s: %w", plan.staging, err)
	}
	listed := strings.Join(columns, ", ")
	if err := m.connection.Exec(ctx, "INSERT INTO "+plan.table+" ("+listed+") SELECT "+listed+
		" FROM "+plan.staging+" WHERE toUInt64(splitByChar('_', _part)[3]) > ?", copiedThrough); err != nil {
		return fmt.Errorf("copy what reached %s after block %d: %w", plan.staging, copiedThrough, err)
	}
	if err := m.connection.Exec(ctx, "DROP TABLE "+plan.staging+" SYNC"); err != nil {
		return fmt.Errorf("drop %s: %w", plan.staging, err)
	}
	m.logger.Info("table_rebuild_finished",
		slog.String("table", plan.table), slog.Uint64("copied_again_after_block", copiedThrough))
	return nil
}

// system.detached_tables also lists tables that were dropped, so whether a table
// was left detached is asked of ATTACH itself.
func (m *Migrator) reattach(ctx context.Context, table string) (bool, error) {
	err := m.connection.Exec(ctx, "ATTACH TABLE "+table)
	var exception *clickhouse.Exception
	if errors.As(err, &exception) && (exception.Code == unknownTable || exception.Code == noTableToAttach) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("attach %s: %w", table, err)
	}
	return true, nil
}

func (m *Migrator) sortingKey(ctx context.Context, table string) (string, bool, error) {
	rows, err := m.connection.Query(ctx,
		"SELECT sorting_key FROM system.tables WHERE database = currentDatabase() AND name = ?", table)
	if err != nil {
		return "", false, fmt.Errorf("read how %s is ordered: %w", table, err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		return "", false, rows.Err()
	}
	var key string
	if err := rows.Scan(&key); err != nil {
		return "", false, fmt.Errorf("read how %s is ordered: %w", table, err)
	}
	return key, true, rows.Err()
}

func (m *Migrator) partitions(ctx context.Context, table string) ([]string, error) {
	rows, err := m.connection.Query(ctx,
		"SELECT DISTINCT partition_id FROM system.parts WHERE database = currentDatabase() AND table = ? AND active ORDER BY partition_id",
		table)
	if err != nil {
		return nil, fmt.Errorf("list the partitions of %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()

	var partitions []string
	for rows.Next() {
		var partition string
		if err := rows.Scan(&partition); err != nil {
			return nil, fmt.Errorf("list the partitions of %s: %w", table, err)
		}
		partitions = append(partitions, partition)
	}
	return partitions, rows.Err()
}

func sameKey(a, b string) bool {
	return strings.Join(strings.Fields(a), "") == strings.Join(strings.Fields(b), "")
}
