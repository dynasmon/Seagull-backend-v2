package clickhouse

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstore"
)

const detectionTable = "security_detections"

// The writer and the final migrated schema must name columns in the same order.
var detectionColumns = []string{
	"detection_id",
	"schema_version",

	"rule_id",
	"rule_revision",
	"rule_name",
	"rule_source_catalogue",
	"rule_source_identifier",
	"ruleset_id",

	"severity",
	"technique_tactic",
	"technique_id",
	"technique_name",

	"event_class",
	"tenant_id",
	"agent_id",
	"host_hostname",
	"host_ip",
	"host_os",
	"host_architecture",

	"source_event_ids",
	"event_time",
	"detected_time",

	"evidence_field",
	"evidence_operator",
	"evidence_negated",
	"evidence_held",
	"evidence_absent",

	"aggregation_count",
	"aggregation_threshold",
	"aggregation_window_seconds",
	"aggregation_first_event_time",
	"aggregation_saturated",
	"aggregation_group_field",
	"aggregation_group_value",
	"aggregation_group_absent",
}

func detectionValues(row detectionstore.Row) []any {
	return []any{
		row.DetectionID,
		row.SchemaVersion,

		row.RuleID,
		row.RuleRevision,
		row.RuleName,
		row.RuleSourceCatalogue,
		row.RuleSourceIdentifier,
		row.RulesetID,

		row.Severity,
		row.TechniqueTactic,
		row.TechniqueID,
		row.TechniqueName,

		row.EventClass,
		row.TenantID,
		row.AgentID,
		row.HostHostname,
		row.HostIP,
		row.HostOS,
		row.HostArchitecture,

		row.SourceEventIDs,
		row.EventTime,
		row.DetectedTime,

		row.EvidenceField,
		row.EvidenceOperator,
		row.EvidenceNegated,
		row.EvidenceHeld,
		row.EvidenceAbsent,

		row.AggregationCount,
		row.AggregationThreshold,
		row.AggregationWindowSeconds,
		row.AggregationFirstEventTime,
		row.AggregationSaturated,
		row.AggregationGroupField,
		row.AggregationGroupValue,
		row.AggregationGroupAbsent,
	}
}

// The same server as the event store and a table of its own, which is a
// deliberate answer rather than an accident: telemetry and detections have the
// same shape of workload — append only, immutable, queried by time range — and
// differ only in volume. An alert does not, and is why the third table in this
// database will not be an alert table.
// The same columns in the same order, to read a row back out. A page of a hunt
// is scanned through these, so a column added to `detectionValues` without being
// added here fails `detectionsAgreeWithSchema` rather than shifting every field
// of an answer.
func detectionPointers(row *detectionstore.Row) []any {
	return []any{
		&row.DetectionID,
		&row.SchemaVersion,

		&row.RuleID,
		&row.RuleRevision,
		&row.RuleName,
		&row.RuleSourceCatalogue,
		&row.RuleSourceIdentifier,
		&row.RulesetID,

		&row.Severity,
		&row.TechniqueTactic,
		&row.TechniqueID,
		&row.TechniqueName,

		&row.EventClass,
		&row.TenantID,
		&row.AgentID,
		&row.HostHostname,
		&row.HostIP,
		&row.HostOS,
		&row.HostArchitecture,

		&row.SourceEventIDs,
		&row.EventTime,
		&row.DetectedTime,

		&row.EvidenceField,
		&row.EvidenceOperator,
		&row.EvidenceNegated,
		&row.EvidenceHeld,
		&row.EvidenceAbsent,

		&row.AggregationCount,
		&row.AggregationThreshold,
		&row.AggregationWindowSeconds,
		&row.AggregationFirstEventTime,
		&row.AggregationSaturated,
		&row.AggregationGroupField,
		&row.AggregationGroupValue,
		&row.AggregationGroupAbsent,
	}
}

type DetectionStore struct {
	connection driver.Conn
	database   string
	insert     string
}

func NewDetectionStore(configuration Config) (*DetectionStore, error) {
	if err := detectionsAgreeWithSchema(); err != nil {
		return nil, err
	}

	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}

	return &DetectionStore{
		connection: connection,
		database:   configuration.Database,
		insert:     fmt.Sprintf("INSERT INTO %s (%s)", detectionTable, strings.Join(detectionColumns, ", ")),
	}, nil
}

func (s *DetectionStore) Store(ctx context.Context, rows []detectionstore.Row) error {
	if len(rows) == 0 {
		return nil
	}

	batch, err := s.connection.PrepareBatch(ctx, s.insert)
	if err != nil {
		return fmt.Errorf("open a batch on %s: %w", detectionTable, err)
	}
	for _, row := range rows {
		if err := batch.Append(detectionValues(row)...); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("add detection %s to the batch: %w", row.DetectionID, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("write %d detections to %s: %w", len(rows), detectionTable, err)
	}
	return nil
}

func (s *DetectionStore) Ping(ctx context.Context) error {
	if err := s.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the detection store: %w", err)
	}
	return nil
}

// Refuse writers whose database is behind their embedded schema.
func (s *DetectionStore) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, s.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		names := make([]string, 0, len(outstanding))
		for _, entry := range outstanding {
			names = append(names, entry.String())
		}
		return fmt.Errorf("the detection store is missing %d migration(s): %s — run store-migrator",
			len(outstanding), strings.Join(names, ", "))
	}
	return columnsPresent(ctx, s.connection, s.database, detectionTable, detectionColumns)
}

func (s *DetectionStore) Close() error { return s.connection.Close() }

// Held at construction rather than only in a test, so a schema and an adapter
// that have drifted apart fail where the process starts instead of where the
// first batch is written.
func detectionsAgreeWithSchema() error {
	declared, err := declaredColumns(detectionTable)
	if err != nil {
		return err
	}
	if !slices.Equal(declared, detectionColumns) {
		return fmt.Errorf("the detection store writes %d columns and the migrated schema defines %d: %s versus %s",
			len(detectionColumns), len(declared),
			strings.Join(detectionColumns, ", "), strings.Join(declared, ", "))
	}
	if length := len(detectionValues(detectionstore.Row{})); length != len(detectionColumns) {
		return fmt.Errorf("the detection store names %d columns and supplies %d values", len(detectionColumns), length)
	}
	if length := len(detectionPointers(&detectionstore.Row{})); length != len(detectionColumns) {
		return fmt.Errorf("the detection store names %d columns and reads %d of them back", len(detectionColumns), length)
	}
	return nil
}
