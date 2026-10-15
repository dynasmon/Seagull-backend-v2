package clickhouse

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/assessmentstore"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

const assessmentTable = "agent_assessments"

// The writer and the final migrated schema must name columns in the same order.
var assessmentColumns = []string{
	"tenant_id",
	"agent_id",
	"assessment_id",
	"ingest_time",

	"assessed_at",
	"policy_id",
	"policy_revision",

	"checks",
	"passed",
	"failed",
	"errors",
	"unsupported",
	"not_applicable",

	"assessment",
}

func assessmentValues(row assessmentstore.Row) []any {
	return []any{
		row.TenantID,
		row.AgentID,
		row.AssessmentID,
		row.IngestTime,

		row.AssessedAt,
		row.PolicyID,
		row.PolicyRevision,

		row.Checks,
		row.Passed,
		row.Failed,
		row.Errors,
		row.Unsupported,
		row.NotApplicable,

		string(row.Assessment),
	}
}

type AssessmentStore struct {
	connection driver.Conn
	database   string
	insert     string
}

func NewAssessmentStore(configuration Config) (*AssessmentStore, error) {
	if err := assessmentsAgreeWithSchema(); err != nil {
		return nil, err
	}
	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}
	return &AssessmentStore{
		connection: connection,
		database:   configuration.Database,
		insert:     fmt.Sprintf("INSERT INTO %s (%s)", assessmentTable, strings.Join(assessmentColumns, ", ")),
	}, nil
}

func (s *AssessmentStore) Store(ctx context.Context, rows []assessmentstore.Row) error {
	if len(rows) == 0 {
		return nil
	}
	batch, err := s.connection.PrepareBatch(ctx, s.insert)
	if err != nil {
		return fmt.Errorf("open a batch on %s: %w", assessmentTable, err)
	}
	for _, row := range rows {
		if err := batch.Append(assessmentValues(row)...); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("add assessment %s of agent %s to the batch: %w", row.AssessmentID, row.AgentID, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("write %d rows to %s: %w", len(rows), assessmentTable, err)
	}
	return nil
}

// The newest assessment of each agent asked about, which is its posture, read
// the way the newest status report is: bounded by the agents of one read and
// the tenants the caller holds. An assessment this build cannot read is left
// out, which answers no posture rather than a wrong one.
func (s *AssessmentStore) Postures(ctx context.Context, agents, tenants []string) (map[string]*assessmentv1.Assessment, error) {
	if len(agents) == 0 || len(tenants) == 0 {
		return map[string]*assessmentv1.Assessment{}, nil
	}
	arguments := make([]any, 0, len(tenants)+len(agents))
	for _, tenant := range tenants {
		arguments = append(arguments, tenant)
	}
	for _, agentID := range agents {
		arguments = append(arguments, agentID)
	}

	rows, err := s.connection.Query(ctx,
		"SELECT agent_id, assessment FROM "+assessmentTable+" FINAL"+
			" WHERE tenant_id IN ("+placeholders(len(tenants))+")"+
			" AND agent_id IN ("+placeholders(len(agents))+")"+
			" ORDER BY assessed_at DESC, assessment_id DESC LIMIT 1 BY agent_id",
		arguments...)
	if err != nil {
		return nil, fmt.Errorf("read the newest assessments of agents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	newest := make(map[string]*assessmentv1.Assessment, len(agents))
	for rows.Next() {
		var id, body string
		if err := rows.Scan(&id, &body); err != nil {
			return nil, fmt.Errorf("read the newest assessments of agents: %w", err)
		}
		var assessed assessmentv1.Assessment
		if err := proto.Unmarshal([]byte(body), &assessed); err != nil {
			continue
		}
		newest[id] = &assessed
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the newest assessments of agents: %w", err)
	}
	return newest, nil
}

func (s *AssessmentStore) Ping(ctx context.Context) error {
	if err := s.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the assessment store: %w", err)
	}
	return nil
}

func (s *AssessmentStore) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, s.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		names := make([]string, 0, len(outstanding))
		for _, entry := range outstanding {
			names = append(names, entry.String())
		}
		return fmt.Errorf("the assessment store is missing %d migration(s): %s — run store-migrator",
			len(outstanding), strings.Join(names, ", "))
	}
	return columnsPresent(ctx, s.connection, s.database, assessmentTable, assessmentColumns)
}

func (s *AssessmentStore) Close() error { return s.connection.Close() }

func assessmentsAgreeWithSchema() error {
	declared, err := declaredColumns(assessmentTable)
	if err != nil {
		return err
	}
	if !slices.Equal(declared, assessmentColumns) {
		return fmt.Errorf("the store writes %d columns of %s and the migrated schema defines %d: %s versus %s",
			len(assessmentColumns), assessmentTable, len(declared), strings.Join(assessmentColumns, ", "), strings.Join(declared, ", "))
	}
	if values := len(assessmentValues(assessmentstore.Row{})); values != len(assessmentColumns) {
		return fmt.Errorf("the store names %d columns of %s and supplies %d values", len(assessmentColumns), assessmentTable, values)
	}
	return nil
}
