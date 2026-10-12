package clickhouse

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/statusstore"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const statusTable = "agent_status"

// The writer and the final migrated schema must name columns in the same order.
var statusColumns = []string{
	"tenant_id",
	"agent_id",
	"ingest_time",

	"reported_at",
	"installation_id",
	"sequence",
	"boot_id",
	"interval_ms",
	"condition",
	"build_version",

	"report",
}

func statusValues(row statusstore.Row) []any {
	return []any{
		row.TenantID,
		row.AgentID,
		row.IngestTime,

		row.ReportedAt,
		row.InstallationID,
		row.Sequence,
		row.BootID,
		row.IntervalMillis,
		row.Condition,
		row.BuildVersion,

		string(row.Report),
	}
}

type StatusStore struct {
	connection driver.Conn
	database   string
	insert     string
}

func NewStatusStore(configuration Config) (*StatusStore, error) {
	if err := statusAgreesWithSchema(); err != nil {
		return nil, err
	}
	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}
	return &StatusStore{
		connection: connection,
		database:   configuration.Database,
		insert:     fmt.Sprintf("INSERT INTO %s (%s)", statusTable, strings.Join(statusColumns, ", ")),
	}, nil
}

func (s *StatusStore) Store(ctx context.Context, rows []statusstore.Row) error {
	if len(rows) == 0 {
		return nil
	}
	batch, err := s.connection.PrepareBatch(ctx, s.insert)
	if err != nil {
		return fmt.Errorf("open a batch on %s: %w", statusTable, err)
	}
	for _, row := range rows {
		if err := batch.Append(statusValues(row)...); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("add report %d of agent %s to the batch: %w", row.Sequence, row.AgentID, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("write %d rows to %s: %w", len(rows), statusTable, err)
	}
	return nil
}

func (s *StatusStore) Ping(ctx context.Context) error {
	if err := s.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the status store: %w", err)
	}
	return nil
}

func (s *StatusStore) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, s.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		names := make([]string, 0, len(outstanding))
		for _, entry := range outstanding {
			names = append(names, entry.String())
		}
		return fmt.Errorf("the status store is missing %d migration(s): %s — run store-migrator",
			len(outstanding), strings.Join(names, ", "))
	}
	return columnsPresent(ctx, s.connection, s.database, statusTable, statusColumns)
}

func (s *StatusStore) Close() error { return s.connection.Close() }

func statusAgreesWithSchema() error {
	declared, err := declaredColumns(statusTable)
	if err != nil {
		return err
	}
	if !slices.Equal(declared, statusColumns) {
		return fmt.Errorf("the store writes %d columns of %s and the migrated schema defines %d: %s versus %s",
			len(statusColumns), statusTable, len(declared), strings.Join(statusColumns, ", "), strings.Join(declared, ", "))
	}
	if values := len(statusValues(statusstore.Row{})); values != len(statusColumns) {
		return fmt.Errorf("the store names %d columns of %s and supplies %d values", len(statusColumns), statusTable, values)
	}
	return nil
}

// The newest report of each agent asked about, read the way `LastSeen` reads
// telemetry: bounded by the agents of one page and the tenants the caller
// holds, so a list costs what the page costs. A report this build cannot read
// is left out, which answers no liveness rather than a wrong one.
func (l *Liveness) Newest(ctx context.Context, agents, tenants []string) (map[string]agentstatus.Report, error) {
	if len(agents) == 0 || len(tenants) == 0 {
		return map[string]agentstatus.Report{}, nil
	}
	arguments := make([]any, 0, len(tenants)+len(agents))
	for _, tenant := range tenants {
		arguments = append(arguments, tenant)
	}
	for _, agentID := range agents {
		arguments = append(arguments, agentID)
	}

	rows, err := l.connection.Query(ctx,
		"SELECT agent_id, ingest_time, report FROM "+statusTable+" FINAL"+
			" WHERE tenant_id IN ("+placeholders(len(tenants))+")"+
			" AND agent_id IN ("+placeholders(len(agents))+")",
		arguments...)
	if err != nil {
		return nil, fmt.Errorf("read what agents last reported: %w", err)
	}
	defer func() { _ = rows.Close() }()

	newest := make(map[string]agentstatus.Report, len(agents))
	for rows.Next() {
		var (
			held agentstatus.Report
			id   string
			body string
		)
		if err := rows.Scan(&id, &held.Received, &body); err != nil {
			return nil, fmt.Errorf("read what agents last reported: %w", err)
		}
		var report agentv1.Status
		if err := proto.Unmarshal([]byte(body), &report); err != nil {
			continue
		}
		held.Received, held.Status = held.Received.UTC(), &report
		if previous, found := newest[id]; !found || held.Received.After(previous.Received) {
			newest[id] = held
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read what agents last reported: %w", err)
	}
	return newest, nil
}
