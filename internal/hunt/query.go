package hunt

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

// How much of a query there may be, over and above how much of the store it may
// read. A caller who needs a wider question than this is asking for a report, and
// a report is not a hunt.
const (
	maxPredicates      = 32
	maxExpressionDepth = 8
)

const (
	CodeUnscoped        = "unscoped"
	CodeUnknownDataset  = "unknown_dataset"
	CodeMissingRange    = "missing_range"
	CodeInvertedRange   = "inverted_range"
	CodeRangeTooWide    = "range_too_wide"
	CodeLimitTooLarge   = "limit_too_large"
	CodeUnknownField    = "unknown_field"
	CodeUnknownOperator = "unknown_operator"
	CodeOperatorRefused = "operator_refused"
	CodeWrongValueCount = "wrong_value_count"
	CodeUnreadableValue = "unreadable_value"
	CodeQueryTooLarge   = "query_too_large"
	CodeQueryTooDeep    = "query_too_deep"
	CodeEmptyGroup      = "empty_group"
	CodeEmptyTerm       = "empty_term"
	CodeInvalidCursor   = "invalid_cursor"
)

// Why a query was not answered, in a shape the transport can hand back whole.
type Refusal struct {
	Code   string
	Detail string
	Field  string
}

func (r *Refusal) Error() string {
	if r.Field == "" {
		return r.Code + ": " + r.Detail
	}
	return fmt.Sprintf("%s: %s (%s)", r.Code, r.Detail, r.Field)
}

func refusal(code, field, detail string, arguments ...any) *Refusal {
	return &Refusal{Code: code, Field: field, Detail: fmt.Sprintf(detail, arguments...)}
}

// Half open: the start is included and the end is not, so consecutive windows
// tile a timeline instead of both claiming the instant between them.
type TimeRange struct {
	Start time.Time
	End   time.Time
}

func (r TimeRange) Width() time.Duration { return r.End.Sub(r.Start) }

// How much of the store one question may read. An executable chooses the
// numbers; the source is expected to hold the read to them and to stop rather
// than to answer late.
type Limits struct {
	Window      time.Duration
	Page        int
	MaxPage     int
	Timeout     time.Duration
	MaxRowsRead uint64
}

func (l Limits) valid() error {
	switch {
	case l.Window <= 0:
		return errors.New("a query plane needs a widest window")
	case l.Page <= 0 || l.MaxPage <= 0 || l.Page > l.MaxPage:
		return errors.New("a query plane needs a page size no larger than its ceiling")
	case l.Timeout <= 0:
		return errors.New("a query plane needs a positive read budget")
	case l.MaxRowsRead == 0:
		return errors.New("a query plane needs a ceiling on how much of the store one read examines")
	}
	return nil
}

// A question the store can be asked, already held to everything that decides
// what it may read. Its parts are unexported and it is only ever built by a
// compiler, so a source cannot be handed a query that carries no scope.
type Query struct {
	dataset     Dataset
	scope       Scope
	window      TimeRange
	where       Expression
	limit       int
	after       After
	limits      Limits
	fingerprint [sha256.Size]byte
}

func (q Query) Dataset() Dataset       { return q.dataset }
func (q Query) Scope() Scope           { return q.scope }
func (q Query) Range() TimeRange       { return q.window }
func (q Query) Where() Expression      { return q.where }
func (q Query) Limit() int             { return q.limit }
func (q Query) After() After           { return q.after }
func (q Query) Timeout() time.Duration { return q.limits.Timeout }
func (q Query) MaxRowsRead() uint64    { return q.limits.MaxRowsRead }

func (q Query) String() string {
	written := strings.Builder{}
	fmt.Fprintf(&written, "%s in %s..%s for %s",
		q.dataset, q.window.Start.Format(time.RFC3339), q.window.End.Format(time.RFC3339),
		strings.Join(q.scope.Tenants(), ","))
	if q.where != nil {
		written.WriteString(" where " + render(q.where))
	}
	return written.String()
}

// Everything that decides which records a page holds and in which order, so that
// a cursor is only ever spent on the question it came from.
func fingerprintOf(dataset Dataset, scope Scope, window TimeRange, where Expression, limit int) [sha256.Size]byte {
	written := strings.Builder{}
	fmt.Fprintf(&written, "%s\n%s\n%d\n%d\n%d\n",
		dataset, strings.Join(scope.Tenants(), ","),
		window.Start.UnixMilli(), window.End.UnixMilli(), limit)
	if where != nil {
		written.WriteString(render(where))
	}
	return sha256.Sum256([]byte(written.String()))
}

type CompilerOptions struct {
	Limits    Limits
	CursorKey []byte
}

// Turns what a caller asked into what the store may be asked, or refuses it.
type Compiler struct {
	limits Limits
	key    []byte
}

func NewCompiler(options CompilerOptions) (*Compiler, error) {
	if err := options.Limits.valid(); err != nil {
		return nil, err
	}
	if len(options.CursorKey) < 32 {
		return nil, errors.New("a query plane needs a cursor key of at least 32 bytes")
	}
	return &Compiler{limits: options.Limits, key: options.CursorKey}, nil
}

func (c *Compiler) Limits() Limits { return c.limits }

func (c *Compiler) Compile(dataset Dataset, scope Scope, asked *huntv1.Query) (Query, error) {
	if scope.Empty() {
		return Query{}, refusal(CodeUnscoped, "", "a query is answered within a scope and this caller has none")
	}
	if !Known(dataset) {
		return Query{}, refusal(CodeUnknownDataset, "", "%q is not a dataset", dataset)
	}

	window, err := c.window(asked.GetRange())
	if err != nil {
		return Query{}, err
	}
	limit, err := c.page(asked.GetLimit())
	if err != nil {
		return Query{}, err
	}

	budget := maxPredicates
	where, err := c.expression(dataset, asked.GetWhere(), 0, &budget)
	if err != nil {
		return Query{}, err
	}

	query := Query{
		dataset:     dataset,
		scope:       scope,
		window:      window,
		where:       where,
		limit:       limit,
		limits:      c.limits,
		fingerprint: fingerprintOf(dataset, scope, window, where, limit),
	}

	if token := asked.GetCursor(); token != "" {
		after, err := decodeCursor(c.key, query.fingerprint, token)
		if err != nil {
			return Query{}, refusal(CodeInvalidCursor, "cursor", "%s", err)
		}
		query.after = after
	}
	return query, nil
}

// The token that resumes this query after the record given, or empty when the
// page was the last one.
func (c *Compiler) Next(query Query, at time.Time, id string) string {
	return encodeCursor(c.key, query.fingerprint, at, id)
}

func (c *Compiler) window(asked *huntv1.TimeRange) (TimeRange, error) {
	if asked.GetStart() == nil || asked.GetEnd() == nil {
		return TimeRange{}, refusal(CodeMissingRange, "range",
			"a query carries the window it asks about; the store holds more than any question should read")
	}

	window := TimeRange{Start: asked.GetStart().AsTime().UTC(), End: asked.GetEnd().AsTime().UTC()}
	switch {
	case !window.End.After(window.Start):
		return TimeRange{}, refusal(CodeInvertedRange, "range", "the range ends at or before it starts")
	case window.Width() > c.limits.Window:
		return TimeRange{}, refusal(CodeRangeTooWide, "range",
			"the range spans %s and the widest a query may ask for is %s", window.Width(), c.limits.Window)
	}
	return window, nil
}

func (c *Compiler) page(asked uint32) (int, error) {
	if asked == 0 {
		return c.limits.Page, nil
	}
	if int64(asked) > int64(c.limits.MaxPage) {
		return 0, refusal(CodeLimitTooLarge, "limit", "a page holds at most %d records", c.limits.MaxPage)
	}
	return int(asked), nil
}

func (c *Compiler) expression(dataset Dataset, asked *huntv1.Expression, depth int, budget *int) (Expression, error) {
	if asked == nil {
		return nil, nil
	}
	if depth > maxExpressionDepth {
		return nil, refusal(CodeQueryTooDeep, "where", "a query may nest %d levels deep", maxExpressionDepth)
	}

	switch form := asked.GetForm().(type) {
	case *huntv1.Expression_Predicate:
		return c.predicate(dataset, form.Predicate, budget)
	case *huntv1.Expression_All:
		terms, err := c.group(dataset, form.All, depth, budget)
		if err != nil {
			return nil, err
		}
		return All{Terms: terms}, nil
	case *huntv1.Expression_Any:
		terms, err := c.group(dataset, form.Any, depth, budget)
		if err != nil {
			return nil, err
		}
		return Any{Terms: terms}, nil
	case *huntv1.Expression_Negated:
		term, err := c.expression(dataset, form.Negated, depth+1, budget)
		if err != nil {
			return nil, err
		}
		if term == nil {
			return nil, refusal(CodeEmptyTerm, "where", "a negation carries nothing to negate")
		}
		return Not{Term: term}, nil
	default:
		return nil, refusal(CodeEmptyTerm, "where", "a term of the query says nothing")
	}
}

func (c *Compiler) group(dataset Dataset, asked *huntv1.Group, depth int, budget *int) ([]Expression, error) {
	written := asked.GetTerms()
	if len(written) == 0 {
		return nil, refusal(CodeEmptyGroup, "where", "a group carries no terms, which is neither true nor false")
	}

	terms := make([]Expression, 0, len(written))
	for _, one := range written {
		term, err := c.expression(dataset, one, depth+1, budget)
		if err != nil {
			return nil, err
		}
		if term == nil {
			return nil, refusal(CodeEmptyTerm, "where", "a term of the group says nothing")
		}
		terms = append(terms, term)
	}
	return terms, nil
}

func (c *Compiler) predicate(dataset Dataset, asked *huntv1.Predicate, budget *int) (Expression, error) {
	if *budget--; *budget < 0 {
		return nil, refusal(CodeQueryTooLarge, "where", "a query asks at most %d questions", maxPredicates)
	}

	field := Field(asked.GetField())
	entry, declared := lookup(dataset, field)
	if !declared {
		return nil, refusal(CodeUnknownField, string(field),
			"%s carries no field named %q", dataset, field)
	}

	operator, known := operators[asked.GetOperator()]
	if !known {
		return nil, refusal(CodeUnknownOperator, string(field),
			"the operators are %s", join(Operators()))
	}
	if !operator.asks(entry.kind) {
		return nil, refusal(CodeOperatorRefused, string(field),
			"%s holds %s and %s does not ask that", field, entry.kind, operator)
	}
	if entry.repeated && !containsOperator(acceptsList, operator) {
		return nil, refusal(CodeOperatorRefused, string(field),
			"the store keeps %s as a list, which answers %s and nothing else", field, join(acceptsList))
	}

	values, err := c.values(entry, field, operator, asked.GetValues())
	if err != nil {
		return nil, err
	}
	return Predicate{Field: field, Operator: operator, Values: values}, nil
}

func (c *Compiler) values(entry held, field Field, operator Operator, written []string) ([]Value, error) {
	minimum, maximum := operator.takes()
	if len(written) < minimum || len(written) > maximum {
		return nil, refusal(CodeWrongValueCount, string(field),
			"%s reads between %d and %d literals and was given %d", operator, minimum, maximum, len(written))
	}

	values := make([]Value, 0, len(written))
	for _, one := range written {
		value, err := literal(entry, one)
		if err != nil {
			return nil, refusal(CodeUnreadableValue, string(field), "%s", err)
		}
		values = append(values, value)
	}
	return values, nil
}

var operators = map[huntv1.Operator]Operator{
	huntv1.Operator_OPERATOR_EQUALS:      Equals,
	huntv1.Operator_OPERATOR_ONE_OF:      OneOf,
	huntv1.Operator_OPERATOR_CONTAINS:    Contains,
	huntv1.Operator_OPERATOR_STARTS_WITH: StartsWith,
	huntv1.Operator_OPERATOR_ENDS_WITH:   EndsWith,
	huntv1.Operator_OPERATOR_ABOVE:       Above,
	huntv1.Operator_OPERATOR_AT_LEAST:    AtLeast,
	huntv1.Operator_OPERATOR_BELOW:       Below,
	huntv1.Operator_OPERATOR_AT_MOST:     AtMost,
	huntv1.Operator_OPERATOR_PRESENT:     Present,
}

func containsOperator(known []Operator, wanted Operator) bool {
	for _, one := range known {
		if one == wanted {
			return true
		}
	}
	return false
}

func join(known []Operator) string {
	written := make([]string, 0, len(known))
	for _, one := range known {
		written = append(written, string(one))
	}
	return strings.Join(written, ", ")
}
