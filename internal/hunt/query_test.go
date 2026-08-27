package hunt_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

var day = time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)

func limits() hunt.Limits {
	return hunt.Limits{
		Window:      720 * time.Hour,
		Page:        50,
		MaxPage:     500,
		Timeout:     250 * time.Millisecond,
		MaxRowsRead: 1_000_000,
	}
}

func compiler(t *testing.T) *hunt.Compiler {
	t.Helper()

	built, err := hunt.NewCompiler(hunt.CompilerOptions{Limits: limits(), CursorKey: []byte(strings.Repeat("k", 32))})
	if err != nil {
		t.Fatalf("build the compiler: %v", err)
	}
	return built
}

func scoped(t *testing.T, tenants ...string) hunt.Scope {
	t.Helper()

	scope, err := hunt.NewScope(tenants)
	if err != nil {
		t.Fatalf("build the scope: %v", err)
	}
	return scope
}

func window(width time.Duration) *huntv1.TimeRange {
	return &huntv1.TimeRange{Start: timestamppb.New(day.Add(-width)), End: timestamppb.New(day)}
}

func asked(where *huntv1.Expression) *huntv1.Query {
	return &huntv1.Query{Range: window(time.Hour), Where: where}
}

func predicate(field string, operator huntv1.Operator, values ...string) *huntv1.Expression {
	return &huntv1.Expression{Form: &huntv1.Expression_Predicate{
		Predicate: &huntv1.Predicate{Field: field, Operator: operator, Values: values},
	}}
}

func refusedAs(t *testing.T, err error, code string) {
	t.Helper()

	var refusal *hunt.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("wanted a refusal and got %v", err)
	}
	if refusal.Code != code {
		t.Fatalf("refused as %q and wanted %q: %s", refusal.Code, code, refusal.Detail)
	}
}

func TestAQueryIsNotCompiledWithoutAScope(t *testing.T) {
	_, err := compiler(t).Compile(hunt.Events, hunt.Scope{}, asked(nil))
	refusedAs(t, err, hunt.CodeUnscoped)
}

func TestTheScopeSurvivesIntoTheQuery(t *testing.T) {
	query, err := compiler(t).Compile(hunt.Events, scoped(t, "acme"), asked(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if tenants := query.Scope().Tenants(); len(tenants) != 1 || tenants[0] != "acme" {
		t.Errorf("the query is answered for %v", tenants)
	}
}

// The range is what makes a question answerable at all, so it is required, it
// cannot run backwards, and it cannot reach further than the plane allows.
func TestTheRangeIsRequiredAndBounded(t *testing.T) {
	built, scope := compiler(t), scoped(t, "acme")

	_, err := built.Compile(hunt.Events, scope, &huntv1.Query{})
	refusedAs(t, err, hunt.CodeMissingRange)

	_, err = built.Compile(hunt.Events, scope, &huntv1.Query{
		Range: &huntv1.TimeRange{Start: timestamppb.New(day), End: timestamppb.New(day.Add(-time.Hour))},
	})
	refusedAs(t, err, hunt.CodeInvertedRange)

	_, err = built.Compile(hunt.Events, scope, &huntv1.Query{Range: window(721 * time.Hour)})
	refusedAs(t, err, hunt.CodeRangeTooWide)

	if _, err := built.Compile(hunt.Events, scope, &huntv1.Query{Range: window(720 * time.Hour)}); err != nil {
		t.Errorf("the widest window a query may ask for was refused: %v", err)
	}
}

func TestAPageHasACeilingAndADefault(t *testing.T) {
	built, scope := compiler(t), scoped(t, "acme")

	query, err := built.Compile(hunt.Events, scope, asked(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if query.Limit() != 50 {
		t.Errorf("a query that asked for no limit reads %d records", query.Limit())
	}

	_, err = built.Compile(hunt.Events, scope, &huntv1.Query{Range: window(time.Hour), Limit: 501})
	refusedAs(t, err, hunt.CodeLimitTooLarge)
}

func TestAQuestionAboutSomethingTheStoreDoesNotHoldIsRefused(t *testing.T) {
	_, err := compiler(t).Compile(hunt.Events, scoped(t, "acme"),
		asked(predicate("authentication.user.password", huntv1.Operator_OPERATOR_EQUALS, "hunter2")))
	refusedAs(t, err, hunt.CodeUnknownField)
}

func TestAnOperatorTheFieldCannotAnswerIsRefused(t *testing.T) {
	built, scope := compiler(t), scoped(t, "acme")

	_, err := built.Compile(hunt.Events, scope,
		asked(predicate("collection.sequence", huntv1.Operator_OPERATOR_CONTAINS, "4")))
	refusedAs(t, err, hunt.CodeOperatorRefused)

	_, err = built.Compile(hunt.Events, scope,
		asked(predicate("authentication.user.name", huntv1.Operator_OPERATOR_UNSPECIFIED, "root")))
	refusedAs(t, err, hunt.CodeUnknownOperator)
}

// A column the store keeps as a list answers whether it carries a value, and
// nothing about how one entry of it compares to another.
func TestAListAnswersOnlyWhatAListCanAnswer(t *testing.T) {
	built, scope := compiler(t), scoped(t, "acme")

	_, err := built.Compile(hunt.Detections, scope,
		asked(predicate("source_event_ids", huntv1.Operator_OPERATOR_STARTS_WITH, "aaaa")))
	refusedAs(t, err, hunt.CodeOperatorRefused)

	if _, err := built.Compile(hunt.Detections, scope,
		asked(predicate("source_event_ids", huntv1.Operator_OPERATOR_EQUALS, "aaaa-1111"))); err != nil {
		t.Errorf("asking whether a list carries a value was refused: %v", err)
	}
}

func TestALiteralIsHeldToWhatTheFieldCarries(t *testing.T) {
	built, scope := compiler(t), scoped(t, "acme")

	for name, term := range map[string]*huntv1.Expression{
		"a number that is not one":   predicate("collection.sequence", huntv1.Operator_OPERATOR_ABOVE, "many"),
		"a choice nobody declared":   predicate("authentication.outcome", huntv1.Operator_OPERATOR_EQUALS, "maybe"),
		"an instant that is not one": predicate("time.observed_time", huntv1.Operator_OPERATOR_BELOW, "yesterday"),
		"a literal beyond the ceiling": predicate("authentication.user.name",
			huntv1.Operator_OPERATOR_EQUALS, strings.Repeat("n", 513)),
	} {
		_, err := built.Compile(hunt.Events, scope, asked(term))
		if err == nil {
			t.Errorf("%s was accepted", name)
			continue
		}
		refusedAs(t, err, hunt.CodeUnreadableValue)
	}
}

func TestAnOperatorReadsTheLiteralsItTakes(t *testing.T) {
	built, scope := compiler(t), scoped(t, "acme")

	_, err := built.Compile(hunt.Events, scope,
		asked(predicate("authentication.user.name", huntv1.Operator_OPERATOR_EQUALS, "root", "admin")))
	refusedAs(t, err, hunt.CodeWrongValueCount)

	_, err = built.Compile(hunt.Events, scope,
		asked(predicate("authentication.user.name", huntv1.Operator_OPERATOR_PRESENT, "root")))
	refusedAs(t, err, hunt.CodeWrongValueCount)

	values := make([]string, 257)
	for index := range values {
		values[index] = "name"
	}
	_, err = built.Compile(hunt.Events, scope,
		asked(predicate("authentication.user.name", huntv1.Operator_OPERATOR_ONE_OF, values...)))
	refusedAs(t, err, hunt.CodeWrongValueCount)
}

// The cost of a query is bounded by how much of it there is as well as by the
// window: a caller cannot spend the store's budget by asking a great many small
// questions in one request.
func TestAQueryIsBoundedInSizeAndDepth(t *testing.T) {
	built, scope := compiler(t), scoped(t, "acme")

	terms := make([]*huntv1.Expression, 33)
	for index := range terms {
		terms[index] = predicate("authentication.user.name", huntv1.Operator_OPERATOR_EQUALS, "root")
	}
	_, err := built.Compile(hunt.Events, scope, asked(&huntv1.Expression{
		Form: &huntv1.Expression_All{All: &huntv1.Group{Terms: terms}},
	}))
	refusedAs(t, err, hunt.CodeQueryTooLarge)

	_, err = built.Compile(hunt.Events, scope, asked(nested(10)))
	refusedAs(t, err, hunt.CodeQueryTooDeep)

	if _, err := built.Compile(hunt.Events, scope, asked(nested(4))); err != nil {
		t.Errorf("a query four groups deep was refused: %v", err)
	}
}

func nested(depth int) *huntv1.Expression {
	term := predicate("authentication.user.name", huntv1.Operator_OPERATOR_EQUALS, "root")
	for range depth {
		term = &huntv1.Expression{Form: &huntv1.Expression_All{All: &huntv1.Group{Terms: []*huntv1.Expression{term}}}}
	}
	return term
}

func TestAGroupThatSaysNothingIsRefused(t *testing.T) {
	built, scope := compiler(t), scoped(t, "acme")

	_, err := built.Compile(hunt.Events, scope, asked(&huntv1.Expression{
		Form: &huntv1.Expression_Any{Any: &huntv1.Group{}},
	}))
	refusedAs(t, err, hunt.CodeEmptyGroup)

	_, err = built.Compile(hunt.Events, scope, asked(&huntv1.Expression{}))
	refusedAs(t, err, hunt.CodeEmptyTerm)
}

// A cursor is spent on the question it came from and on no other, so page two
// cannot arrive with a wider scope, a wider window or different filters than the
// page before it.
func TestACursorBelongsToTheQueryThatIssuedIt(t *testing.T) {
	built := compiler(t)
	first, err := built.Compile(hunt.Events, scoped(t, "acme"), asked(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	token := built.Next(first, day.Add(-time.Minute), "aaaa-1111")
	resumed, err := built.Compile(hunt.Events, scoped(t, "acme"), &huntv1.Query{Range: window(time.Hour), Cursor: token})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if after := resumed.After(); !after.Set || after.ID != "aaaa-1111" || !after.Time.Equal(day.Add(-time.Minute)) {
		t.Errorf("the query resumed at %+v", after)
	}

	for name, spent := range map[string]func() error{
		"a wider scope": func() error {
			_, err := built.Compile(hunt.Events, scoped(t, "acme", "globex"), &huntv1.Query{Range: window(time.Hour), Cursor: token})
			return err
		},
		"a different window": func() error {
			_, err := built.Compile(hunt.Events, scoped(t, "acme"), &huntv1.Query{Range: window(2 * time.Hour), Cursor: token})
			return err
		},
		"a different filter": func() error {
			_, err := built.Compile(hunt.Events, scoped(t, "acme"), &huntv1.Query{
				Range:  window(time.Hour),
				Where:  predicate("authentication.user.name", huntv1.Operator_OPERATOR_EQUALS, "root"),
				Cursor: token,
			})
			return err
		},
		"a different dataset": func() error {
			_, err := built.Compile(hunt.Detections, scoped(t, "acme"), &huntv1.Query{Range: window(time.Hour), Cursor: token})
			return err
		},
		"a token somebody composed": func() error {
			_, err := built.Compile(hunt.Events, scoped(t, "acme"), &huntv1.Query{
				Range: window(time.Hour), Cursor: "YWFhYQ.YmJiYg",
			})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) { refusedAs(t, spent(), hunt.CodeInvalidCursor) })
	}
}

func TestACompilerNeedsLimitsAndAKey(t *testing.T) {
	if _, err := hunt.NewCompiler(hunt.CompilerOptions{CursorKey: []byte(strings.Repeat("k", 32))}); err == nil {
		t.Error("a compiler was built with no limits")
	}
	if _, err := hunt.NewCompiler(hunt.CompilerOptions{Limits: limits(), CursorKey: []byte("short")}); err == nil {
		t.Error("a compiler was built with a key nobody could rely on")
	}
}
