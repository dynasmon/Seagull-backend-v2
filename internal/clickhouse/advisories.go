package clickhouse

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisorystore"
)

const (
	advisoryTable = "vulnerability_advisories"
	affectedTable = "vulnerability_affected"
	feedSyncTable = "vulnerability_feed_syncs"
)

// The writer and the final migrated schema must name columns in the same order.
var advisoryColumns = []string{
	"source",
	"advisory_id",
	"modified",
	"normalization",
	"schema_version",
	"published",
	"withdrawn",
	"aliases",
	"upstream",
	"related",
	"summary",
	"details",
	"severity_types",
	"severity_scores",
	"severity_assessors",
	"affected",
	"feed",
	"feed_version",
	"location",
	"fetched_at",
	"digest",
	"format",
}

var affectedColumns = []string{
	"ecosystem",
	"package",
	"source",
	"advisory_id",
	"modified",
	"normalization",
	"entry",
	"range_types",
	"event_ranges",
	"event_kinds",
	"event_versions",
	"versions",
	"severity_types",
	"severity_scores",
	"severity_assessors",
	"withdrawn",
}

var feedSyncColumns = []string{
	"source",
	"feed",
	"checked_at",
	"outcome",
	"synced_at",
	"newest_listed",
	"feed_version",
	"listed",
	"held",
	"published",
	"refused",
	"failure",
}

func advisoryValues(row advisorystore.AdvisoryRow) []any {
	return []any{
		row.Source,
		row.AdvisoryID,
		row.Modified,
		row.Normalization,
		row.SchemaVersion,
		row.Published,
		row.Withdrawn,
		listed(row.Aliases),
		listed(row.Upstream),
		listed(row.Related),
		row.Summary,
		row.Details,
		listed(row.SeverityTypes),
		listed(row.SeverityScores),
		listed(row.SeverityAssessors),
		row.Affected,
		row.Feed,
		row.FeedVersion,
		row.Location,
		row.FetchedAt,
		row.Digest,
		row.Format,
	}
}

func affectedValues(row advisorystore.AffectedRow) []any {
	ranges := row.EventRanges
	if ranges == nil {
		ranges = []uint32{}
	}
	return []any{
		row.Ecosystem,
		row.Package,
		row.Source,
		row.AdvisoryID,
		row.Modified,
		row.Normalization,
		row.Entry,
		listed(row.RangeTypes),
		ranges,
		listed(row.EventKinds),
		listed(row.EventVersions),
		listed(row.Versions),
		listed(row.SeverityTypes),
		listed(row.SeverityScores),
		listed(row.SeverityAssessors),
		row.Withdrawn,
	}
}

func feedSyncValues(row advisorystore.SyncRow) []any {
	return []any{
		row.Source,
		row.Feed,
		row.CheckedAt,
		row.Outcome,
		row.SyncedAt,
		row.NewestListed,
		row.FeedVersion,
		row.Listed,
		row.Held,
		row.Published,
		row.Refused,
		row.Failure,
	}
}

type AdvisoryStore struct {
	connection     driver.Conn
	database       string
	insertAdvisory string
	insertAffected string
	insertFeedSync string
}

func NewAdvisoryStore(configuration Config) (*AdvisoryStore, error) {
	if err := advisoriesAgreeWithSchema(); err != nil {
		return nil, err
	}

	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}

	return &AdvisoryStore{
		connection:     connection,
		database:       configuration.Database,
		insertAdvisory: fmt.Sprintf("INSERT INTO %s (%s)", advisoryTable, strings.Join(advisoryColumns, ", ")),
		insertAffected: fmt.Sprintf("INSERT INTO %s (%s)", affectedTable, strings.Join(affectedColumns, ", ")),
		insertFeedSync: fmt.Sprintf("INSERT INTO %s (%s)", feedSyncTable, strings.Join(feedSyncColumns, ", ")),
	}, nil
}

// What a version affects lands before the version itself, and the syncs that
// vouch for both land last: a reader that finds a version finds everything it
// affects, and one that reads a feed as fresh finds everything that made it so.
func (s *AdvisoryStore) Store(ctx context.Context, projected advisorystore.Projection) error {
	if err := s.write(ctx, s.insertAffected, affectedTable, len(projected.Affected), func(batch driver.Batch) error {
		for _, row := range projected.Affected {
			if err := batch.Append(affectedValues(row)...); err != nil {
				return fmt.Errorf("add %s %s of %s to the batch: %w", row.Ecosystem, row.Package, row.AdvisoryID, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if err := s.write(ctx, s.insertAdvisory, advisoryTable, len(projected.Advisories), func(batch driver.Batch) error {
		for _, row := range projected.Advisories {
			if err := batch.Append(advisoryValues(row)...); err != nil {
				return fmt.Errorf("add %s to the batch: %w", row.AdvisoryID, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return s.write(ctx, s.insertFeedSync, feedSyncTable, len(projected.Syncs), func(batch driver.Batch) error {
		for _, row := range projected.Syncs {
			if err := batch.Append(feedSyncValues(row)...); err != nil {
				return fmt.Errorf("add the sync of %s to the batch: %w", row.Feed, err)
			}
		}
		return nil
	})
}

func (s *AdvisoryStore) write(ctx context.Context, statement, table string, count int, fill func(driver.Batch) error) error {
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

func (s *AdvisoryStore) Ping(ctx context.Context) error {
	if err := s.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the advisory store: %w", err)
	}
	return nil
}

func (s *AdvisoryStore) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, s.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		names := make([]string, 0, len(outstanding))
		for _, entry := range outstanding {
			names = append(names, entry.String())
		}
		return fmt.Errorf("the advisory store is missing %d migration(s): %s — run store-migrator",
			len(outstanding), strings.Join(names, ", "))
	}
	for _, table := range []struct {
		name    string
		columns []string
	}{
		{advisoryTable, advisoryColumns},
		{affectedTable, affectedColumns},
		{feedSyncTable, feedSyncColumns},
	} {
		if err := columnsPresent(ctx, s.connection, s.database, table.name, table.columns); err != nil {
			return err
		}
	}
	return nil
}

func (s *AdvisoryStore) Close() error { return s.connection.Close() }

func advisoriesAgreeWithSchema() error {
	for _, agreement := range []struct {
		table   string
		columns []string
		values  int
	}{
		{advisoryTable, advisoryColumns, len(advisoryValues(advisorystore.AdvisoryRow{}))},
		{affectedTable, affectedColumns, len(affectedValues(advisorystore.AffectedRow{}))},
		{feedSyncTable, feedSyncColumns, len(feedSyncValues(advisorystore.SyncRow{}))},
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
