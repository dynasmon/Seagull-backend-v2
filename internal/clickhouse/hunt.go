package clickhouse

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// Where a field of the contract is kept. This is the only mapping of its kind in
// the platform and it runs one way, from the contract towards the store: a query
// is written in the vocabulary the record declares, and the column is an
// implementation detail of this file. `agreesWithVocabulary` refuses a build
// where the two have drifted apart, so a contract field with nowhere to live
// stops the process rather than silently answering nothing.
var huntColumns = map[hunt.Dataset]map[hunt.Field]string{
	hunt.Events: {
		"event_id":                                "event_id",
		"schema_version":                          "schema_version",
		"event_class":                             "event_class",
		"time.event_time":                         "event_time",
		"time.observed_time":                      "observed_time",
		"reception.ingest_time":                   "ingest_time",
		"reception.gateway":                       "gateway",
		"reception.batch_id":                      "batch_id",
		"origin.tenant_id":                        "tenant_id",
		"origin.agent_id":                         "agent_id",
		"origin.host.hostname":                    "host_hostname",
		"origin.host.ip":                          "host_ip",
		"origin.host.os":                          "host_os",
		"origin.host.architecture":                "host_architecture",
		"collection.collector":                    "collector",
		"collection.source":                       "source",
		"collection.sequence":                     "sequence",
		"authentication.activity":                 "auth_activity",
		"authentication.outcome":                  "auth_outcome",
		"authentication.outcome_reason":           "auth_outcome_reason",
		"authentication.method":                   "auth_method",
		"authentication.user.name":                "auth_user_name",
		"authentication.user.domain":              "auth_user_domain",
		"authentication.user.uid":                 "auth_user_uid",
		"authentication.service.name":             "auth_service_name",
		"authentication.service.protocol":         "auth_service_protocol",
		"authentication.network.source.ip":        "auth_source_ip",
		"authentication.network.source.port":      "auth_source_port",
		"authentication.network.destination.ip":   "auth_destination_ip",
		"authentication.network.destination.port": "auth_destination_port",
		"authentication.network.transport":        "auth_transport",
		"authentication.raw_record":               "auth_raw_record",
	},
	hunt.Detections: {
		"detection_id":             "detection_id",
		"schema_version":           "schema_version",
		"rule.id":                  "rule_id",
		"rule.revision":            "rule_revision",
		"rule.name":                "rule_name",
		"rule.source.catalogue":    "rule_source_catalogue",
		"rule.source.identifier":   "rule_source_identifier",
		"ruleset_id":               "ruleset_id",
		"severity":                 "severity",
		"technique.tactic":         "technique_tactic",
		"technique.id":             "technique_id",
		"technique.name":           "technique_name",
		"event_class":              "event_class",
		"origin.tenant_id":         "tenant_id",
		"origin.agent_id":          "agent_id",
		"origin.host.hostname":     "host_hostname",
		"origin.host.ip":           "host_ip",
		"origin.host.os":           "host_os",
		"origin.host.architecture": "host_architecture",
		"source_event_ids":         "source_event_ids",
		"event_time":               "event_time",
		"detected_time":            "detected_time",
		"evidence.field":           "evidence_field",
		"evidence.operator":        "evidence_operator",
		"evidence.negated":         "evidence_negated",
		"evidence.held":            "evidence_held",
		"evidence.absent":          "evidence_absent",

		"aggregation.count":            "aggregation_count",
		"aggregation.threshold":        "aggregation_threshold",
		"aggregation.first_event_time": "aggregation_first_event_time",
		"aggregation.saturated":        "aggregation_saturated",
		"aggregation.group.field":      "aggregation_group_field",
		"aggregation.group.value":      "aggregation_group_value",
		"aggregation.group.absent":     "aggregation_group_absent",
	},
}

// What each dataset is read out of, and the pair its rows are ordered and
// resumed by. Both tables sort by the instant the thing happened and then by the
// name of the record, so a page resumes at exactly the pair the last row carried.
var huntTables = map[hunt.Dataset]struct {
	table   string
	columns []string
	instant string
	name    string
}{
	hunt.Events:     {table, storedColumns, "event_time", "event_id"},
	hunt.Detections: {detectionTable, detectionColumns, "event_time", "detection_id"},
}

// The driver renders a bound instant to whole seconds, which would silently drop
// the millisecond both stores keep — a window that excludes the records it was
// meant to include, and a cursor that steps over everything inside the second it
// resumes from. Milliseconds are bound as a number and rebuilt server-side.
const instantPlaceholder = "fromUnixTimestamp64Milli(?, 'UTC')"

// Reads what the writers wrote. It holds the only read connection to the
// analytical store and writes nothing: a plane that answers questions cannot
// change the evidence it is answering from.
type Hunter struct {
	connection driver.Conn
	database   string
}

func NewHunter(configuration Config) (*Hunter, error) {
	if err := agreesWithVocabulary(); err != nil {
		return nil, err
	}

	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}
	return &Hunter{connection: connection, database: configuration.Database}, nil
}

func (h *Hunter) Close() error { return h.connection.Close() }

func (h *Hunter) Ping(ctx context.Context) error {
	if err := h.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the store: %w", err)
	}
	return nil
}

// Refuse a reader whose database is behind the schema it was built against, for
// the same reason a writer is refused: a missing column is a question answered
// wrongly rather than not at all.
func (h *Hunter) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, h.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		names := make([]string, 0, len(outstanding))
		for _, entry := range outstanding {
			names = append(names, entry.String())
		}
		return fmt.Errorf("the store is missing %d migration(s): %s — run store-migrator",
			len(outstanding), strings.Join(names, ", "))
	}
	if err := columnsPresent(ctx, h.connection, h.database, table, storedColumns); err != nil {
		return err
	}
	return columnsPresent(ctx, h.connection, h.database, detectionTable, detectionColumns)
}

func (h *Hunter) Events(ctx context.Context, query hunt.Query) ([]*eventv1.Event, error) {
	var found []*eventv1.Event
	err := h.read(ctx, query, func(rows driver.Rows) error {
		var row eventstore.Row
		if err := rows.Scan(eventPointers(&row)...); err != nil {
			return err
		}
		found = append(found, eventstore.Restore(row))
		return nil
	})
	return found, err
}

func (h *Hunter) Detections(ctx context.Context, query hunt.Query) ([]*detectionv1.Detection, error) {
	var found []*detectionv1.Detection
	err := h.read(ctx, query, func(rows driver.Rows) error {
		var row detectionstore.Row
		if err := rows.Scan(detectionPointers(&row)...); err != nil {
			return err
		}
		found = append(found, detectionstore.Restore(row))
		return nil
	})
	return found, err
}

// The budget travels with the query rather than with the connection, so one
// caller cannot spend another caller's allowance, and the store stops the read
// itself instead of being abandoned mid-scan.
func (h *Hunter) read(ctx context.Context, query hunt.Query, take func(driver.Rows) error) error {
	statement, arguments, err := compile(query)
	if err != nil {
		return err
	}

	budgeted := clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{
		"max_execution_time":    int(math.Ceil(query.Timeout().Seconds())),
		"timeout_overflow_mode": "throw",
		"max_rows_to_read":      query.MaxRowsRead(),
		"read_overflow_mode":    "throw",
	}))

	rows, err := h.connection.Query(budgeted, statement, arguments...)
	if err != nil {
		return fmt.Errorf("ask the store: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		if err := take(rows); err != nil {
			return fmt.Errorf("read a row of the answer: %w", err)
		}
	}
	return rows.Err()
}

// FINAL, because a replayed record is a second row until the parts holding it
// are merged, and an analyst reading the same event twice has no way to tell
// that from the same thing happening twice.
func compile(query hunt.Query) (string, []any, error) {
	dataset := huntTables[query.Dataset()]

	conditions := []string{"tenant_id IN (" + placeholders(len(query.Scope().Tenants())) + ")"}
	arguments := make([]any, 0, 8)
	for _, tenant := range query.Scope().Tenants() {
		arguments = append(arguments, tenant)
	}

	conditions = append(conditions,
		dataset.instant+" >= "+instantPlaceholder+" AND "+dataset.instant+" < "+instantPlaceholder)
	arguments = append(arguments, query.Range().Start.UnixMilli(), query.Range().End.UnixMilli())

	if after := query.After(); after.Set {
		conditions = append(conditions,
			"("+dataset.instant+", "+dataset.name+") < ("+instantPlaceholder+", ?)")
		arguments = append(arguments, after.Time.UnixMilli(), after.ID)
	}

	if where := query.Where(); where != nil {
		written, values, err := condition(query.Dataset(), where)
		if err != nil {
			return "", nil, err
		}
		conditions = append(conditions, written)
		arguments = append(arguments, values...)
	}

	statement := fmt.Sprintf("SELECT %s FROM %s FINAL WHERE %s ORDER BY %s DESC, %s DESC LIMIT %d",
		strings.Join(dataset.columns, ", "), dataset.table, strings.Join(conditions, " AND "),
		dataset.instant, dataset.name, query.Limit())
	return statement, arguments, nil
}

func condition(dataset hunt.Dataset, term hunt.Expression) (string, []any, error) {
	switch shape := term.(type) {
	case hunt.Predicate:
		return predicate(dataset, shape)
	case hunt.All:
		return group(dataset, shape.Terms, " AND ")
	case hunt.Any:
		return group(dataset, shape.Terms, " OR ")
	case hunt.Not:
		written, values, err := condition(dataset, shape.Term)
		if err != nil {
			return "", nil, err
		}
		return "NOT " + written, values, nil
	default:
		return "", nil, fmt.Errorf("the store cannot read a %T", term)
	}
}

func group(dataset hunt.Dataset, terms []hunt.Expression, separator string) (string, []any, error) {
	written := make([]string, 0, len(terms))
	values := make([]any, 0, len(terms))
	for _, term := range terms {
		one, arguments, err := condition(dataset, term)
		if err != nil {
			return "", nil, err
		}
		written = append(written, one)
		values = append(values, arguments...)
	}
	return "(" + strings.Join(written, separator) + ")", values, nil
}

// A field the store keeps as a list is asked whether it carries a value, never
// how one entry of it compares to another. Two questions about two lists of the
// same record are two questions about the columns, not about one entry: evidence
// is five arrays read sideways, and correlating a position across them is a
// different question this plane does not yet ask.
func predicate(dataset hunt.Dataset, asked hunt.Predicate) (string, []any, error) {
	column, mapped := huntColumns[dataset][asked.Field]
	if !mapped {
		return "", nil, fmt.Errorf("the store keeps no column for %s", asked.Field)
	}
	kind, _ := hunt.KindOf(dataset, asked.Field)
	repeated := hunt.Repeated(dataset, asked.Field)

	if asked.Operator == hunt.Present {
		return present(column, kind, repeated)
	}
	if repeated {
		return carries(column, asked)
	}

	held := placeholder(kind)
	switch asked.Operator {
	case hunt.Equals:
		return column + " = " + held, bind(asked.Values), nil
	case hunt.OneOf:
		return column + " IN (" + placeholders(len(asked.Values)) + ")", bind(asked.Values), nil
	case hunt.Contains:
		return "position(" + column + ", ?) > 0", bind(asked.Values), nil
	case hunt.StartsWith:
		return "startsWith(" + column + ", ?)", bind(asked.Values), nil
	case hunt.EndsWith:
		return "endsWith(" + column + ", ?)", bind(asked.Values), nil
	case hunt.Above:
		return column + " > " + held, bind(asked.Values), nil
	case hunt.AtLeast:
		return column + " >= " + held, bind(asked.Values), nil
	case hunt.Below:
		return column + " < " + held, bind(asked.Values), nil
	case hunt.AtMost:
		return column + " <= " + held, bind(asked.Values), nil
	default:
		return "", nil, fmt.Errorf("the store cannot ask %s of %s", asked.Operator, asked.Field)
	}
}

func placeholder(kind hunt.Kind) string {
	if kind == hunt.Instant {
		return instantPlaceholder
	}
	return "?"
}

func carries(column string, asked hunt.Predicate) (string, []any, error) {
	written := make([]string, 0, len(asked.Values))
	for range asked.Values {
		written = append(written, "has("+column+", ?)")
	}
	return "(" + strings.Join(written, " OR ") + ")", bind(asked.Values), nil
}

// The contract has no way to say a field is absent — proto3 writes the zero
// value and the store keeps exactly that — so presence is asking whether the
// record carries anything at all, and a boolean that is false carries nothing.
func present(column string, kind hunt.Kind, repeated bool) (string, []any, error) {
	if repeated {
		return "notEmpty(" + column + ")", nil, nil
	}
	switch kind {
	case hunt.Number:
		return column + " != 0", nil, nil
	case hunt.Truth:
		return column + " = true", nil, nil
	case hunt.Instant:
		return column + " != " + instantPlaceholder, []any{int64(0)}, nil
	default:
		return column + " != ''", nil, nil
	}
}

// A number written without a fraction is bound as one, so a comparison against
// an unsigned column stays exact past the range a float can name.
func bind(values []hunt.Value) []any {
	bound := make([]any, 0, len(values))
	for _, value := range values {
		switch value.Kind() {
		case hunt.Number:
			if whole, exact := value.Whole(); exact {
				bound = append(bound, whole)
				continue
			}
			bound = append(bound, value.Number())
		case hunt.Truth:
			bound = append(bound, value.Truth())
		case hunt.Instant:
			bound = append(bound, value.Instant().UnixMilli())
		default:
			bound = append(bound, value.Text())
		}
	}
	return bound
}

func placeholders(count int) string {
	if count <= 0 {
		return "NULL"
	}
	return strings.TrimSuffix(strings.Repeat("?, ", count), ", ")
}

// Held at construction rather than only in a test, so a contract field with no
// column, or a column no question can name, stops the process where it starts.
func agreesWithVocabulary() error {
	for _, dataset := range hunt.Datasets() {
		mapped, declared := huntColumns[dataset]
		if !declared {
			return fmt.Errorf("no column is named for any field of %s", dataset)
		}
		read := huntTables[dataset]

		for _, field := range hunt.Fields(dataset) {
			column, found := mapped[field]
			if !found {
				return fmt.Errorf("%s carries %s and the store names no column for it", dataset, field)
			}
			if !slices.Contains(read.columns, column) {
				return fmt.Errorf("%s.%s is read from %s, which %s does not have", dataset, field, column, read.table)
			}
		}
		if len(mapped) != len(hunt.Fields(dataset)) {
			return fmt.Errorf("%s names %d columns and the contract declares %d fields",
				dataset, len(mapped), len(hunt.Fields(dataset)))
		}
	}
	return nil
}
