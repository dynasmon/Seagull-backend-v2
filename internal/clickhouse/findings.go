package clickhouse

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/internal/findingstore"
)

const (
	findingTable           = "vulnerability_findings"
	findingAssessmentTable = "vulnerability_assessments"
)

// The writer and the final migrated schema must name columns in the same order.
var findingColumns = []string{
	"tenant_id",
	"agent_id",
	"item_id",
	"vulnerability_id",
	"opened_at",
	"state",

	"inventory_as_of",
	"intelligence_as_of",
	"decided_at",

	"unassessable",
	"package_name",
	"package_version",
	"advised_ecosystem",
	"advised_package",
	"fix",
	"severity_type",
	"severity_score",

	"record",
}

var findingAssessmentColumns = []string{
	"tenant_id",
	"agent_id",
	"scope",
	"inventory_as_of",
	"intelligence_as_of",
	"decided_at",

	"stale",
	"unassessable",
	"open",
	"closed",
	"unassessed",

	"record",
}

func findingValues(row findingstore.FindingRow) []any {
	return []any{
		row.TenantID,
		row.AgentID,
		row.ItemID,
		row.VulnerabilityID,
		row.OpenedAt,
		row.State,

		row.InventoryAsOf,
		row.IntelligenceAsOf,
		row.DecidedAt,

		row.Unassessable,
		row.PackageName,
		row.PackageVersion,
		row.AdvisedEcosystem,
		row.AdvisedPackage,
		row.Fix,
		row.SeverityType,
		row.SeverityScore,

		string(row.Record),
	}
}

func findingAssessmentValues(row findingstore.AssessmentRow) []any {
	return []any{
		row.TenantID,
		row.AgentID,
		row.Scope,
		row.InventoryAsOf,
		row.IntelligenceAsOf,
		row.DecidedAt,

		row.Stale,
		row.Unassessable,
		row.Open,
		row.Closed,
		row.Unassessed,

		string(row.Record),
	}
}

type FindingStore struct {
	connection        driver.Conn
	database          string
	insertFindings    string
	insertAssessments string
}

func NewFindingStore(configuration Config) (*FindingStore, error) {
	if err := findingsAgreeWithSchema(); err != nil {
		return nil, err
	}
	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}
	return &FindingStore{
		connection:        connection,
		database:          configuration.Database,
		insertFindings:    fmt.Sprintf("INSERT INTO %s (%s)", findingTable, strings.Join(findingColumns, ", ")),
		insertAssessments: fmt.Sprintf("INSERT INTO %s (%s)", findingAssessmentTable, strings.Join(findingAssessmentColumns, ", ")),
	}, nil
}

// The findings land before the assessments they were decided in: a reader
// holding an asset's findings to its newest whole assessment must never see an
// assessment whose findings have not landed.
func (s *FindingStore) Store(ctx context.Context, findings []findingstore.FindingRow, assessments []findingstore.AssessmentRow) error {
	if err := s.write(ctx, s.insertFindings, findingTable, len(findings), func(batch driver.Batch) error {
		for _, row := range findings {
			if err := batch.Append(findingValues(row)...); err != nil {
				return fmt.Errorf("add the finding %s of agent %s to the batch: %w", row.VulnerabilityID, row.AgentID, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return s.write(ctx, s.insertAssessments, findingAssessmentTable, len(assessments), func(batch driver.Batch) error {
		for _, row := range assessments {
			if err := batch.Append(findingAssessmentValues(row)...); err != nil {
				return fmt.Errorf("add the %s assessment of agent %s to the batch: %w", row.Scope, row.AgentID, err)
			}
		}
		return nil
	})
}

func (s *FindingStore) write(ctx context.Context, statement, table string, count int, fill func(driver.Batch) error) error {
	if count == 0 {
		return nil
	}
	batch, err := s.connection.PrepareBatch(ctx, statement)
	if err != nil {
		return fmt.Errorf("open a batch on %s: %w", table, err)
	}
	if err := fill(batch); err != nil {
		_ = batch.Abort()
		return err
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("write %d rows to %s: %w", count, table, err)
	}
	return nil
}

func (s *FindingStore) Ping(ctx context.Context) error {
	if err := s.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the finding store: %w", err)
	}
	return nil
}

func (s *FindingStore) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, s.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		names := make([]string, 0, len(outstanding))
		for _, entry := range outstanding {
			names = append(names, entry.String())
		}
		return fmt.Errorf("the finding store is missing %d migration(s): %s — run store-migrator",
			len(outstanding), strings.Join(names, ", "))
	}
	if err := columnsPresent(ctx, s.connection, s.database, findingTable, findingColumns); err != nil {
		return err
	}
	return columnsPresent(ctx, s.connection, s.database, findingAssessmentTable, findingAssessmentColumns)
}

func (s *FindingStore) Close() error { return s.connection.Close() }

func findingsAgreeWithSchema() error {
	for _, agreement := range []struct {
		table   string
		columns []string
		values  int
	}{
		{findingTable, findingColumns, len(findingValues(findingstore.FindingRow{}))},
		{findingAssessmentTable, findingAssessmentColumns, len(findingAssessmentValues(findingstore.AssessmentRow{}))},
	} {
		declared, err := declaredColumns(agreement.table)
		if err != nil {
			return err
		}
		if !slices.Equal(declared, agreement.columns) {
			return fmt.Errorf("the store writes %d columns of %s and the migrated schema defines %d: %s versus %s",
				len(agreement.columns), agreement.table, len(declared),
				strings.Join(agreement.columns, ", "), strings.Join(declared, ", "))
		}
		if agreement.values != len(agreement.columns) {
			return fmt.Errorf("the store names %d columns of %s and supplies %d values",
				len(agreement.columns), agreement.table, agreement.values)
		}
	}
	return nil
}
