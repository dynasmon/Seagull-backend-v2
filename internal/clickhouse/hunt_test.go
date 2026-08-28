package clickhouse

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

var noon = time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)

func query(t *testing.T, dataset hunt.Dataset, where *huntv1.Expression, tenants ...string) hunt.Query {
	t.Helper()

	compiler, err := hunt.NewCompiler(hunt.CompilerOptions{
		Limits: hunt.Limits{
			Window: 720 * time.Hour, Page: 50, MaxPage: 500,
			Timeout: 15 * time.Second, MaxRowsRead: 1_000_000,
		},
		CursorKey: []byte(strings.Repeat("k", 32)),
	})
	if err != nil {
		t.Fatalf("build the compiler: %v", err)
	}
	scope, err := hunt.NewScope(tenants)
	if err != nil {
		t.Fatalf("build the scope: %v", err)
	}

	built, err := compiler.Compile(dataset, scope, &huntv1.Query{
		Range: &huntv1.TimeRange{Start: timestamppb.New(noon.Add(-time.Hour)), End: timestamppb.New(noon)},
		Where: where,
	})
	if err != nil {
		t.Fatalf("compile the query: %v", err)
	}
	return built
}

func asking(field string, operator huntv1.Operator, values ...string) *huntv1.Expression {
	return &huntv1.Expression{Form: &huntv1.Expression_Predicate{
		Predicate: &huntv1.Predicate{Field: field, Operator: operator, Values: values},
	}}
}

func statementFor(t *testing.T, dataset hunt.Dataset, where *huntv1.Expression) (string, []any) {
	t.Helper()

	statement, arguments, err := compile(query(t, dataset, where, "acme"))
	if err != nil {
		t.Fatalf("compile to sql: %v", err)
	}
	return statement, arguments
}

// The mapping runs one way, from the contract towards the store, and it is total
// in both directions: a field with nowhere to live and a column no question can
// name are both refusals, and both are found where the process starts.
func TestEveryFieldAQueryMayNameHasAColumn(t *testing.T) {
	if err := agreesWithVocabulary(); err != nil {
		t.Fatalf("the vocabulary and the schema have drifted apart: %v", err)
	}
}

// No literal a caller wrote ever reaches the text of the statement. Every one of
// them is a placeholder the driver binds, so a query cannot be composed by
// whoever asked it.
func TestNoLiteralEverReachesTheStatement(t *testing.T) {
	statement, arguments := statementFor(t, hunt.Events, &huntv1.Expression{
		Form: &huntv1.Expression_All{All: &huntv1.Group{Terms: []*huntv1.Expression{
			asking("authentication.user.name", huntv1.Operator_OPERATOR_EQUALS, "root' OR 1=1 --"),
			asking("authentication.outcome", huntv1.Operator_OPERATOR_ONE_OF, "failure", "success"),
			asking("collection.sequence", huntv1.Operator_OPERATOR_ABOVE, "41"),
		}}},
	})

	for _, written := range []string{"root' OR 1=1 --", "failure", "success", "41"} {
		if strings.Contains(statement, written) {
			t.Errorf("the literal %q reached the statement: %s", written, statement)
		}
	}
	if placeholders := strings.Count(statement, "?"); placeholders != len(arguments) {
		t.Errorf("the statement holds %d placeholders and %d arguments were bound: %s",
			placeholders, len(arguments), statement)
	}
}

// The scope is the first thing the store is asked about and it is not optional,
// so there is no shape of query that reads outside it.
func TestEveryStatementIsBoundedByTheScopeAndTheWindow(t *testing.T) {
	for _, dataset := range hunt.Datasets() {
		statement, arguments := statementFor(t, dataset, nil)

		if !strings.Contains(statement, "tenant_id IN (?)") {
			t.Errorf("%s is read without a scope: %s", dataset, statement)
		}
		if !strings.Contains(statement,
			"event_time >= fromUnixTimestamp64Milli(?, 'UTC') AND event_time < fromUnixTimestamp64Milli(?, 'UTC')") {
			t.Errorf("%s is read without a window: %s", dataset, statement)
		}
		if arguments[0] != "acme" {
			t.Errorf("%s was read for %v", dataset, arguments[0])
		}
	}
}

// FINAL, because a replayed record is a second row until the parts holding it
// are merged, and an analyst reading the same event twice cannot tell that from
// the same thing happening twice.
func TestAnAnswerNeverShowsAReplayedRecordTwice(t *testing.T) {
	for _, dataset := range hunt.Datasets() {
		statement, _ := statementFor(t, dataset, nil)
		if !strings.Contains(statement, " FINAL ") {
			t.Errorf("%s is read without collapsing a replay: %s", dataset, statement)
		}
	}
}

// Newest first, and resumed by the pair the table is sorted by rather than by a
// count of records already seen.
func TestAPageIsOrderedAndResumedByTheSortKey(t *testing.T) {
	statement, _ := statementFor(t, hunt.Events, nil)
	if !strings.Contains(statement, "ORDER BY event_time DESC, event_id DESC LIMIT 50") {
		t.Errorf("a page is not the newest fifty records: %s", statement)
	}
	if strings.Contains(statement, "(event_time, event_id) <") {
		t.Errorf("a first page was read as though it were resuming: %s", statement)
	}

	compiler, err := hunt.NewCompiler(hunt.CompilerOptions{
		Limits: hunt.Limits{
			Window: 720 * time.Hour, Page: 50, MaxPage: 500,
			Timeout: 15 * time.Second, MaxRowsRead: 1_000_000,
		},
		CursorKey: []byte(strings.Repeat("k", 32)),
	})
	if err != nil {
		t.Fatalf("build the compiler: %v", err)
	}
	first := query(t, hunt.Events, nil, "acme")
	scope, _ := hunt.NewScope([]string{"acme"})
	resumed, err := compiler.Compile(hunt.Events, scope, &huntv1.Query{
		Range:  &huntv1.TimeRange{Start: timestamppb.New(noon.Add(-time.Hour)), End: timestamppb.New(noon)},
		Cursor: compiler.Next(first, noon.Add(-time.Minute), "aaaa"),
	})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}

	statement, arguments, err := compile(resumed)
	if err != nil {
		t.Fatalf("compile to sql: %v", err)
	}
	if !strings.Contains(statement, "(event_time, event_id) < (fromUnixTimestamp64Milli(?, 'UTC'), ?)") {
		t.Errorf("a resumed page does not carry on from the last record: %s", statement)
	}
	if arguments[len(arguments)-1] != "aaaa" {
		t.Errorf("the page resumed after %v", arguments[len(arguments)-1])
	}
}

func TestEachOperatorBecomesTheQuestionItAsks(t *testing.T) {
	for name, expected := range map[string]struct {
		term *huntv1.Expression
		sql  string
	}{
		"equals":      {asking("authentication.user.name", huntv1.Operator_OPERATOR_EQUALS, "root"), "auth_user_name = ?"},
		"one of":      {asking("authentication.user.name", huntv1.Operator_OPERATOR_ONE_OF, "root", "admin"), "auth_user_name IN (?, ?)"},
		"contains":    {asking("authentication.raw_record", huntv1.Operator_OPERATOR_CONTAINS, "sshd"), "position(auth_raw_record, ?) > 0"},
		"starts with": {asking("origin.host.hostname", huntv1.Operator_OPERATOR_STARTS_WITH, "web"), "startsWith(host_hostname, ?)"},
		"ends with":   {asking("origin.host.hostname", huntv1.Operator_OPERATOR_ENDS_WITH, ".example"), "endsWith(host_hostname, ?)"},
		"above":       {asking("collection.sequence", huntv1.Operator_OPERATOR_ABOVE, "41"), "sequence > ?"},
		"at least":    {asking("collection.sequence", huntv1.Operator_OPERATOR_AT_LEAST, "41"), "sequence >= ?"},
		"below":       {asking("time.observed_time", huntv1.Operator_OPERATOR_BELOW, "2026-08-26T11:00:00Z"), "observed_time < fromUnixTimestamp64Milli(?, 'UTC')"},
		"at most":     {asking("collection.sequence", huntv1.Operator_OPERATOR_AT_MOST, "41"), "sequence <= ?"},
	} {
		statement, _ := statementFor(t, hunt.Events, expected.term)
		if !strings.Contains(statement, expected.sql) {
			t.Errorf("%s became %s, wanted %s", name, statement, expected.sql)
		}
	}
}

// A field the store keeps as a list is asked whether it carries a value, which
// is what makes it possible to walk from an event to the detections made from it.
func TestAListIsAskedWhetherItCarriesAValue(t *testing.T) {
	statement, arguments := statementFor(t, hunt.Detections,
		asking("source_event_ids", huntv1.Operator_OPERATOR_EQUALS, "aaaa-1111"))
	if !strings.Contains(statement, "(has(source_event_ids, ?))") {
		t.Errorf("a list was not asked what it carries: %s", statement)
	}
	if arguments[len(arguments)-1] != "aaaa-1111" {
		t.Errorf("the list was asked about %v", arguments[len(arguments)-1])
	}

	statement, _ = statementFor(t, hunt.Detections,
		asking("evidence.field", huntv1.Operator_OPERATOR_ONE_OF, "authentication.outcome", "authentication.method"))
	if !strings.Contains(statement, "(has(evidence_field, ?) OR has(evidence_field, ?))") {
		t.Errorf("a list was not asked about either value: %s", statement)
	}
}

// The contract has no way to say a field is absent — proto3 writes the zero
// value and the store keeps exactly that — so presence is asking whether the
// record carries anything at all.
func TestPresenceIsAskedOfWhatTheKindCanHold(t *testing.T) {
	for name, expected := range map[string]struct {
		dataset hunt.Dataset
		term    *huntv1.Expression
		sql     string
	}{
		"text":    {hunt.Events, asking("authentication.user.name", huntv1.Operator_OPERATOR_PRESENT), "auth_user_name != ''"},
		"number":  {hunt.Events, asking("collection.sequence", huntv1.Operator_OPERATOR_PRESENT), "sequence != 0"},
		"instant": {hunt.Events, asking("reception.ingest_time", huntv1.Operator_OPERATOR_PRESENT), "ingest_time != fromUnixTimestamp64Milli(?, 'UTC')"},
		"a list":  {hunt.Detections, asking("source_event_ids", huntv1.Operator_OPERATOR_PRESENT), "notEmpty(source_event_ids)"},
		"truth":   {hunt.Detections, asking("evidence.negated", huntv1.Operator_OPERATOR_PRESENT), "notEmpty(evidence_negated)"},
	} {
		statement, _ := statementFor(t, expected.dataset, expected.term)
		if !strings.Contains(statement, expected.sql) {
			t.Errorf("presence of %s became %s, wanted %s", name, statement, expected.sql)
		}
	}
}

func TestAGroupBecomesTheBooleanItStatesFor(t *testing.T) {
	statement, _ := statementFor(t, hunt.Events, &huntv1.Expression{
		Form: &huntv1.Expression_Negated{Negated: &huntv1.Expression{
			Form: &huntv1.Expression_Any{Any: &huntv1.Group{Terms: []*huntv1.Expression{
				asking("origin.agent_id", huntv1.Operator_OPERATOR_EQUALS, "web-01"),
				asking("origin.agent_id", huntv1.Operator_OPERATOR_EQUALS, "web-02"),
			}}},
		}},
	})
	if !strings.Contains(statement, "NOT (agent_id = ? OR agent_id = ?)") {
		t.Errorf("a negated disjunction became %s", statement)
	}
}

// The driver renders a bound instant to whole seconds. A window and a cursor that
// lost their millisecond would silently step over every record inside the second
// they resume from, so an instant crosses as a number and is rebuilt in the store.
func TestAnInstantCrossesAsAMillisecond(t *testing.T) {
	_, arguments := statementFor(t, hunt.Events,
		asking("time.observed_time", huntv1.Operator_OPERATOR_AT_MOST, "2026-08-26T11:00:00.123Z"))

	bound, ok := arguments[len(arguments)-1].(int64)
	if !ok {
		t.Fatalf("an instant was bound as %T", arguments[len(arguments)-1])
	}
	if wanted := time.Date(2026, time.August, 26, 11, 0, 0, 123_000_000, time.UTC).UnixMilli(); bound != wanted {
		t.Errorf("the store was asked about %d and the query said %d", bound, wanted)
	}
}

// An integral literal is bound as an integer, so a comparison against an
// unsigned column stays exact past the range a float can name.
func TestAWholeNumberIsBoundAsOne(t *testing.T) {
	_, arguments := statementFor(t, hunt.Events,
		asking("collection.sequence", huntv1.Operator_OPERATOR_ABOVE, "9007199254740993"))

	bound, ok := arguments[len(arguments)-1].(int64)
	if !ok {
		t.Fatalf("a whole number was bound as %T", arguments[len(arguments)-1])
	}
	if bound != 9007199254740993 {
		t.Errorf("the store was asked about %d", bound)
	}
}
