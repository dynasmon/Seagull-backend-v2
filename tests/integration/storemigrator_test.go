//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	chgo "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
)

const (
	rebuiltKey    = "tenant_id, event_time, agent_id, event_id"
	rebuiltEngine = "ReplacingMergeTree(arrival_precedence)"
	rebuildTable  = "security_events_rebuild"
	schemaOnDisk  = "../../internal/clickhouse/schema"
	rebuildTenant = "rebuilt"
)

var (
	releasedColumns = []string{"event_id", "event_time", "tenant_id", "agent_id"}
	rebuildsOnDisk  = []struct {
		migration int
		file      string
	}{
		{9, "0009_order_security_events_by_agent.sql"},
		{13, "0013_security_events_log_position.sql"},
	}
)

// Every test here migrates a database of its own, so the state a previous
// release left behind can be built and watched without disturbing the store the
// other suites share.
func freshDatabase(t *testing.T, address string) (string, driver.Conn) {
	t.Helper()

	name := fmt.Sprintf("rebuild_%d", time.Now().UnixNano())
	administer := inspector(t, address)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := administer.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = administer.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" SYNC")
	})

	connection, err := chgo.Open(&chgo.Options{
		Addr:     []string{address},
		Auth:     chgo.Auth{Database: name, Username: storeUser},
		Settings: chgo.Settings{"async_insert": 0},
	})
	if err != nil {
		t.Fatalf("connect to %s: %v", name, err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return name, connection
}

func settingsFor(address, database string) clickhouse.Config {
	settings := storeSettings(address)
	settings.Database = database
	return settings
}

func run(t *testing.T, connection driver.Conn, statement string, arguments ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := connection.Exec(ctx, statement, arguments...); err != nil {
		t.Fatalf("%.80s: %v", statement, err)
	}
}

// What a release left behind: every migration up to its last, applied from the
// files in the tree with a rebuild applied as the table it rebuilds, recorded in
// a ledger shaped like the migrator's, and filled by a writer that knew only the
// columns every release has held.
func releasedThrough(t *testing.T, connection driver.Conn, last int) {
	t.Helper()

	run(t, connection, `CREATE TABLE IF NOT EXISTS schema_migrations
(
    version    UInt32,
    name       String,
    applied_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY version`)

	files, err := filepath.Glob(filepath.Join(schemaOnDisk, "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("find the schema in the tree: %v", err)
	}
	slices.Sort(files)
	for _, file := range files {
		digits, name, _ := strings.Cut(strings.TrimSuffix(filepath.Base(file), ".sql"), "_")
		version, err := strconv.Atoi(digits)
		if err != nil {
			t.Fatalf("read the version of %s: %v", file, err)
		}
		if version > last {
			continue
		}
		for _, statement := range statementsIn(t, file) {
			if strings.Contains(statement, rebuildTable) {
				run(t, connection, "DROP TABLE IF EXISTS security_events SYNC")
				statement = strings.Replace(statement, rebuildTable, "security_events", 1)
			}
			run(t, connection, statement)
		}
		run(t, connection, "INSERT INTO schema_migrations (version, name) VALUES (?, ?)", uint32(version), name)
	}
}

func statementsIn(t *testing.T, file string) []string {
	t.Helper()

	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var kept []string
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			kept = append(kept, line)
		}
	}
	var statements []string
	for _, statement := range strings.Split(strings.Join(kept, "\n"), ";") {
		if trimmed := strings.TrimSpace(statement); trimmed != "" {
			statements = append(statements, trimmed)
		}
	}
	return statements
}

func migrate(t *testing.T, address, database string) {
	t.Helper()

	migrator, err := clickhouse.NewMigrator(settingsFor(address, database), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("build the migrator: %v", err)
	}
	defer func() { _ = migrator.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := migrator.Apply(ctx); err != nil {
		t.Fatalf("migrate %s: %v", database, err)
	}
}

func sent(agentID, eventID string, at time.Time) eventstore.Row {
	record := fixtures.SSHAuthentication{EventID: eventID, AgentID: agentID, At: at}.Event()
	record.Origin.TenantId = rebuildTenant
	return eventstore.Project(record)
}

func writeAsReleased(t *testing.T, connection driver.Conn, rows ...eventstore.Row) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, row := range rows {
		if err := insertAsReleased(ctx, connection, row); err != nil {
			t.Fatalf("write %s of %s: %v", row.EventID, row.AgentID, err)
		}
	}
}

func insertAsReleased(ctx context.Context, connection driver.Conn, row eventstore.Row) error {
	batch, err := connection.PrepareBatch(ctx, "INSERT INTO security_events ("+strings.Join(releasedColumns, ", ")+")")
	if err != nil {
		return err
	}
	if err := batch.Append(row.EventID, row.EventTime, row.TenantID, row.AgentID); err != nil {
		_ = batch.Abort()
		return err
	}
	return batch.Send()
}

func named(rows ...eventstore.Row) []string {
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.AgentID+"/"+row.EventID+"@"+row.EventTime.UTC().Format(time.RFC3339Nano))
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func held(t *testing.T, connection driver.Conn, table string, final bool) []string {
	t.Helper()

	statement := "SELECT agent_id, event_id, event_time FROM " + table
	if final {
		statement += " FINAL"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rows, err := connection.Query(ctx, statement+" WHERE tenant_id = ?", rebuildTenant)
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var (
			agentID, eventID string
			at               time.Time
		)
		if err := rows.Scan(&agentID, &eventID, &at); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		names = append(names, agentID+"/"+eventID+"@"+at.UTC().Format(time.RFC3339Nano))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	slices.Sort(names)
	if final {
		return names
	}
	return slices.Compact(names)
}

func keptAs(t *testing.T, connection driver.Conn, table string) (string, string, bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rows, err := connection.Query(ctx,
		"SELECT engine_full, sorting_key FROM system.tables WHERE database = currentDatabase() AND name = ?", table)
	if err != nil {
		t.Fatalf("read how %s is kept: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return "", "", false
	}
	var engine, key string
	if err := rows.Scan(&engine, &key); err != nil {
		t.Fatalf("read how %s is kept: %v", table, err)
	}
	return engine, key, true
}

func rebuilt(t *testing.T, connection driver.Conn) {
	t.Helper()

	engine, key, _ := keptAs(t, connection, "security_events")
	if key != rebuiltKey {
		t.Errorf("security_events is ordered by %q, want %q", key, rebuiltKey)
	}
	if !strings.HasPrefix(engine, rebuiltEngine+" ") {
		t.Errorf("security_events is kept by %q, want %s", engine, rebuiltEngine)
	}
	if _, key, found := keptAs(t, connection, rebuildTable); found {
		t.Errorf("%s was left behind, ordered by %q", rebuildTable, key)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := connection.Exec(ctx, "ATTACH TABLE "+rebuildTable); err == nil {
		t.Errorf("%s was left detached", rebuildTable)
	}

	var recorded []uint32
	if err := connection.QueryRow(ctx,
		"SELECT groupArray(version) FROM (SELECT version FROM schema_migrations ORDER BY version)").Scan(&recorded); err != nil {
		t.Fatalf("read the ledger: %v", err)
	}
	for _, rebuild := range rebuildsOnDisk {
		if !slices.Contains(recorded, uint32(rebuild.migration)) {
			t.Errorf("the ledger records %v and not the rebuild of %s", recorded, rebuild.file)
		}
	}
}

func positioned(t *testing.T, connection driver.Conn) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var placed uint64
	if err := connection.QueryRow(ctx,
		"SELECT countIf(log_partition != -1 OR log_offset != -1) FROM security_events WHERE tenant_id = ?",
		rebuildTenant).Scan(&placed); err != nil {
		t.Fatalf("read the positions of the rebuilt store: %v", err)
	}
	return placed
}

func TestAnEmptyStoreIsMigratedToEventsNamedByTheirAgent(t *testing.T) {
	address := storeAddress(t)
	database, connection := freshDatabase(t, address)

	migrate(t, address, database)
	migrate(t, address, database)

	rebuilt(t, connection)
}

// A release kept two agents' events of one identifier and instant, and one
// agent's event delivered twice, as separate parts until a merge collapsed them.
// Merges are held so all are still there to be kept, as they would be in a store
// whose parts had not yet met.
func populated(t *testing.T, address string, last int) (string, driver.Conn, []string) {
	t.Helper()

	database, connection := freshDatabase(t, address)
	releasedThrough(t, connection, last)
	run(t, connection, "SYSTEM STOP MERGES security_events")

	september := time.Date(2026, time.September, 30, 23, 59, 59, 0, time.UTC)
	october := time.Date(2026, time.October, 1, 0, 0, 1, 0, time.UTC)
	written := []eventstore.Row{
		sent("web-01", "aaaaaaaa-0000-4000-8000-000000000001", september),
		sent("web-02", "aaaaaaaa-0000-4000-8000-000000000001", september),
		sent("web-01", "aaaaaaaa-0000-4000-8000-000000000002", october),
		sent("web-01", "aaaaaaaa-0000-4000-8000-000000000002", october),
		sent("web-03", "aaaaaaaa-0000-4000-8000-000000000003", october.Add(time.Millisecond)),
	}
	writeAsReleased(t, connection, written...)

	if before := held(t, connection, "security_events", false); !slices.Equal(before, named(written...)) {
		t.Fatalf("release %d holds %v before the rebuild, want %v", last, before, named(written...))
	}
	return database, connection, named(written...)
}

func TestARebuildKeepsEveryEventOfAPopulatedStore(t *testing.T) {
	address := storeAddress(t)
	for _, rebuild := range rebuildsOnDisk {
		t.Run(rebuild.file, func(t *testing.T) {
			database, connection, want := populated(t, address, rebuild.migration-1)

			migrate(t, address, database)

			rebuilt(t, connection)
			if got := held(t, connection, "security_events", true); !slices.Equal(got, want) {
				t.Errorf("the rebuilt store holds %v, want %v", got, want)
			}
			if placed := positioned(t, connection); placed != 0 {
				t.Errorf("%d rows written before positions were kept were given one", placed)
			}
		})
	}
}

func TestARebuildResumesFromWhereItStopped(t *testing.T) {
	for _, rebuild := range rebuildsOnDisk {
		t.Run(rebuild.file, func(t *testing.T) { resumed(t, rebuild.migration, rebuild.file) })
	}
}

func resumed(t *testing.T, migration int, file string) {
	address := storeAddress(t)
	staging := statementsIn(t, filepath.Join(schemaOnDisk, file))[0]
	columns := strings.Join(releasedColumns, ", ")
	copyOneMonth := func(connection driver.Conn, from, to string) {
		run(t, connection, "INSERT INTO "+to+" ("+columns+") SELECT "+columns+" FROM "+from+" WHERE _partition_id = '202609'")
	}

	for stopped, interrupt := range map[string]func(*testing.T, driver.Conn) eventstore.Row{
		"while the first copy ran": func(t *testing.T, connection driver.Conn) eventstore.Row {
			run(t, connection, staging)
			copyOneMonth(connection, "security_events", rebuildTable)
			return eventstore.Row{}
		},
		"once the tables were exchanged": func(t *testing.T, connection driver.Conn) eventstore.Row {
			run(t, connection, staging)
			copyOneMonth(connection, "security_events", rebuildTable)
			run(t, connection, "EXCHANGE TABLES security_events AND "+rebuildTable)
			late := sent("web-04", "aaaaaaaa-0000-4000-8000-000000000004", time.Date(2026, time.October, 2, 0, 0, 0, 0, time.UTC))
			run(t, connection, "INSERT INTO "+rebuildTable+" ("+columns+") VALUES (?, ?, ?, ?)",
				late.EventID, late.EventTime, late.TenantID, late.AgentID)
			return late
		},
		"while the old table was detached": func(t *testing.T, connection driver.Conn) eventstore.Row {
			run(t, connection, staging)
			copyOneMonth(connection, "security_events", rebuildTable)
			run(t, connection, "EXCHANGE TABLES security_events AND "+rebuildTable)
			run(t, connection, "DETACH TABLE "+rebuildTable+" SYNC")
			return eventstore.Row{}
		},
		"once the old table was dropped": func(t *testing.T, connection driver.Conn) eventstore.Row {
			run(t, connection, staging)
			run(t, connection, "INSERT INTO "+rebuildTable+" ("+columns+") SELECT "+columns+" FROM security_events")
			run(t, connection, "EXCHANGE TABLES security_events AND "+rebuildTable)
			run(t, connection, "DROP TABLE "+rebuildTable+" SYNC")
			return eventstore.Row{}
		},
	} {
		t.Run(stopped, func(t *testing.T) {
			database, connection, want := populated(t, address, migration-1)
			if late := interrupt(t, connection); late.EventID != "" {
				want = slices.Sorted(slices.Values(append(want, named(late)...)))
			}

			migrate(t, address, database)

			rebuilt(t, connection)
			if got := held(t, connection, "security_events", true); !slices.Equal(got, want) {
				t.Errorf("the rebuilt store holds %v, want %v", got, want)
			}
		})
	}
}

func TestEventsWrittenWhileTheStoreIsRebuiltAreKept(t *testing.T) {
	address := storeAddress(t)
	database, connection := freshDatabase(t, address)
	releasedThrough(t, connection, rebuildsOnDisk[0].migration-1)
	run(t, connection, `INSERT INTO security_events (event_id, event_time, tenant_id, agent_id)
		SELECT concat('bulk-', toString(number)), now64(3) - toIntervalMillisecond(number), 'bulk', concat('web-0', toString(number % 4))
		FROM numbers(2000000)`)

	writing, stop := context.WithCancel(context.Background())
	var (
		stored  []eventstore.Row
		refused []error
		group   sync.WaitGroup
	)
	group.Add(1)
	t.Cleanup(func() { stop(); group.Wait() })
	go func() {
		defer group.Done()
		for index := 0; writing.Err() == nil; index++ {
			row := sent(fmt.Sprintf("web-%02d", index%7), fmt.Sprintf("bbbbbbbb-0000-4000-8000-%012d", index),
				time.Now().UTC().Truncate(time.Millisecond))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := insertAsReleased(ctx, connection, row); err != nil {
				refused = append(refused, err)
			} else {
				stored = append(stored, row)
			}
			cancel()
			time.Sleep(2 * time.Millisecond)
		}
	}()

	migrate(t, address, database)
	stop()
	group.Wait()

	rebuilt(t, connection)
	if len(stored) == 0 {
		t.Fatal("nothing was written while the store was rebuilt")
	}
	if len(refused) > 0 {
		t.Errorf("%d of %d writes were refused while the store was rebuilt, the first: %v",
			len(refused), len(refused)+len(stored), refused[0])
	}
	got := held(t, connection, "security_events", true)
	for _, name := range named(stored...) {
		if _, found := slices.BinarySearch(got, name); !found {
			t.Errorf("%s was written while the store was rebuilt and is not in it", name)
		}
	}
	t.Logf("%d events were written while the store was rebuilt", len(stored))
}

func TestAWriteOnItsWayToTheOldTableWhenTheNamesAreExchangedIsKept(t *testing.T) {
	address := storeAddress(t)
	database, connection, want := populated(t, address, rebuildsOnDisk[0].migration-1)

	slow := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		slow <- connection.Exec(ctx, `INSERT INTO security_events (event_id, event_time, tenant_id, agent_id, host_os)
			SELECT concat('slow-', toString(number)), toDateTime64('2026-10-03 00:00:00', 3, 'UTC') + toIntervalMillisecond(number),
			       ?, 'web-09', toString(sleepEachRow(0.5))
			FROM numbers(6) SETTINGS max_block_size = 1`, rebuildTenant)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var running uint64
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := connection.QueryRow(ctx,
			"SELECT count() FROM system.processes WHERE query_kind = 'Insert' AND query LIKE '%slow-%'").Scan(&running)
		cancel()
		if err != nil {
			t.Fatalf("look for the write on its way: %v", err)
		}
		if running > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the slow write never started")
		}
		time.Sleep(20 * time.Millisecond)
	}

	migrate(t, address, database)
	if err := <-slow; err != nil {
		t.Fatalf("the write on its way to the old table failed: %v", err)
	}

	for index := range 6 {
		at := time.Date(2026, time.October, 3, 0, 0, 0, 0, time.UTC).Add(time.Duration(index) * time.Millisecond)
		want = append(want, "web-09/slow-"+strconv.Itoa(index)+"@"+at.Format(time.RFC3339Nano))
	}
	slices.Sort(want)
	rebuilt(t, connection)
	if got := held(t, connection, "security_events", true); !slices.Equal(got, want) {
		t.Errorf("the rebuilt store holds %v, want %v", got, want)
	}
}
