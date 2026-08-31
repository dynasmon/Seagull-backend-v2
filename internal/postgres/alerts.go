package postgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	DefaultPageSize = 50
	MaxPageSize     = 500
)

const columns = `alert_id, schema_version, tenant_id, detection_id,
	rule_id, rule_revision, rule_name, rule_source_catalogue, rule_source_identifier,
	severity, technique_tactic, technique_id, technique_name,
	event_class, agent_id, event_time, raised_at,
	state, assignee, changed_by, changed_at, revision,
	closure_state, closure_reason, closure_by, closure_at,
	correlation_key, occurrences, first_seen, last_seen`

const insertAlert = `INSERT INTO alerts (` + columns + `)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30)
ON CONFLICT (alert_id) DO NOTHING`

const insertTransition = `INSERT INTO alert_transitions
	(alert_id, revision, from_state, to_state, assignee, actor, at, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (alert_id, revision) DO NOTHING`

// Superseded by Record once the writer folds; kept while the writer still calls
// it so that every branch tip compiles.
func (s *Store) Raise(ctx context.Context, raised []*alertv1.Alert) (int, error) {
	candidates := make([]alert.Candidate, 0, len(raised))
	for _, one := range raised {
		candidates = append(candidates, alert.Candidate{
			Alert:       one,
			DetectionID: one.GetDetectionId(),
			Key:         one.GetAlertId(),
			At:          one.GetFirstSeen().AsTime(),
		})
	}
	outcomes, err := s.Record(ctx, candidates)
	if err != nil {
		return 0, err
	}
	added := 0
	for _, outcome := range outcomes {
		if outcome == alert.OutcomeRaised {
			added++
		}
	}
	return added, nil
}

func (s *Store) Alert(ctx context.Context, id string, tenants []string) (*alertv1.Alert, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+columns+" FROM alerts WHERE alert_id = $1 AND tenant_id = ANY($2)", id, tenants)
	if err != nil {
		return nil, fmt.Errorf("read alert %s: %w", id, err)
	}
	found, err := pgx.CollectRows(rows, restore)
	if err != nil {
		return nil, fmt.Errorf("read alert %s: %w", id, err)
	}
	if len(found) == 0 {
		return nil, alert.ErrUnknownAlert
	}
	return found[0], nil
}

func (s *Store) History(ctx context.Context, id string, tenants []string) (*alertv1.History, error) {
	if _, err := s.Alert(ctx, id, tenants); err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx,
		`SELECT alert_id, revision, from_state, to_state, assignee, actor, at, note
		 FROM alert_transitions WHERE alert_id = $1 ORDER BY revision`, id)
	if err != nil {
		return nil, fmt.Errorf("read the trail of alert %s: %w", id, err)
	}
	carried, err := pgx.CollectRows(rows, restoreTransition)
	if err != nil {
		return nil, fmt.Errorf("read the trail of alert %s: %w", id, err)
	}
	return &alertv1.History{AlertId: id, Transitions: carried}, nil
}

// The scope is a predicate on every read and is never composed from the cursor,
// so a position lifted from another caller's page still answers within the
// tenants this caller holds.
func (s *Store) Page(ctx context.Context, asked *alertv1.Query, tenants []string) (*alertv1.Page, error) {
	limit := int(asked.GetLimit())
	if limit <= 0 {
		limit = DefaultPageSize
	}
	limit = min(limit, MaxPageSize)

	where := []string{"tenant_id = ANY($1)"}
	arguments := []any{tenants}
	place := func(value any) string {
		arguments = append(arguments, value)
		return "$" + strconv.Itoa(len(arguments))
	}

	if start := asked.GetRange().GetStart(); start != nil {
		where = append(where, "raised_at >= "+place(start.AsTime().UTC()))
	}
	if end := asked.GetRange().GetEnd(); end != nil {
		where = append(where, "raised_at < "+place(end.AsTime().UTC()))
	}
	if named := states(asked.GetStates()); len(named) > 0 {
		where = append(where, "state = ANY("+place(named)+")")
	}
	if named := severities(asked.GetSeverities()); len(named) > 0 {
		where = append(where, "severity = ANY("+place(named)+")")
	}
	if asked.GetAssignee() != "" {
		where = append(where, "assignee = "+place(asked.GetAssignee()))
	}
	if asked.GetRuleId() != "" {
		where = append(where, "rule_id = "+place(asked.GetRuleId()))
	}
	if asked.GetAgentId() != "" {
		where = append(where, "agent_id = "+place(asked.GetAgentId()))
	}
	if asked.GetCursor() != "" {
		at, id, err := decodeCursor(asked.GetCursor())
		if err != nil {
			return nil, err
		}
		where = append(where, "(raised_at, alert_id) < ("+place(at)+", "+place(id)+")")
	}

	query := "SELECT " + columns + " FROM alerts WHERE " + strings.Join(where, " AND ") +
		" ORDER BY raised_at DESC, alert_id DESC LIMIT " + place(limit+1)

	rows, err := s.pool.Query(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	found, err := pgx.CollectRows(rows, restore)
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}

	page := &alertv1.Page{Alerts: found}
	if len(found) > limit {
		page.Alerts = found[:limit]
		last := page.Alerts[limit-1]
		page.NextCursor = encodeCursor(last.GetRaisedAt().AsTime(), last.GetAlertId())
	}
	return page, nil
}

// Read, decide and write in one transaction with the row held, so the state the
// move was decided against is the state it is applied to. Without the lock two
// analysts could each read `open` and both be allowed to close it.
func (s *Store) Move(ctx context.Context, id string, tenants []string, asked alert.Move) (*alertv1.Alert, error) {
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin moving alert %s: %w", id, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	rows, err := transaction.Query(ctx,
		"SELECT "+columns+" FROM alerts WHERE alert_id = $1 AND tenant_id = ANY($2) FOR UPDATE", id, tenants)
	if err != nil {
		return nil, fmt.Errorf("read alert %s: %w", id, err)
	}
	held, err := pgx.CollectRows(rows, restore)
	if err != nil {
		return nil, fmt.Errorf("read alert %s: %w", id, err)
	}
	if len(held) == 0 {
		return nil, alert.ErrUnknownAlert
	}

	moved, line, err := alert.Apply(held[0], asked)
	if err != nil {
		return nil, err
	}

	if _, err := transaction.Exec(ctx,
		`UPDATE alerts SET state = $2, assignee = $3, changed_by = $4, changed_at = $5, revision = $6,
			closure_state = $7, closure_reason = $8, closure_by = $9, closure_at = $10
		 WHERE alert_id = $1`,
		moved.GetAlertId(),
		state(moved.GetState()), moved.GetAssignee(), moved.GetChangedBy(),
		moved.GetChangedAt().AsTime(), int64(moved.GetRevision()),
		state(moved.GetClosure().GetState()), moved.GetClosure().GetReason(),
		moved.GetClosure().GetClosedBy(), optional(moved.GetClosure().GetClosedAt()),
	); err != nil {
		return nil, fmt.Errorf("move alert %s: %w", id, err)
	}
	if _, err := transaction.Exec(ctx, insertTransition, trail(line)...); err != nil {
		return nil, fmt.Errorf("record the move of alert %s: %w", id, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit the move of alert %s: %w", id, err)
	}
	return moved, nil
}

func stored(one *alertv1.Alert) []any {
	return []any{
		one.GetAlertId(), int32(one.GetSchemaVersion()), one.GetTenantId(), one.GetDetectionId(),
		one.GetRule().GetId(), int64(one.GetRule().GetRevision()), one.GetRule().GetName(),
		one.GetRule().GetSource().GetCatalogue(), one.GetRule().GetSource().GetIdentifier(),
		alert.Severity(one.GetSeverity()),
		one.GetTechnique().GetTactic(), one.GetTechnique().GetId(), one.GetTechnique().GetName(),
		alert.Class(one.GetEventClass()), one.GetAgentId(),
		optional(one.GetEventTime()), one.GetRaisedAt().AsTime(),
		state(one.GetState()), one.GetAssignee(), one.GetChangedBy(),
		one.GetChangedAt().AsTime(), int64(one.GetRevision()),
		state(one.GetClosure().GetState()), one.GetClosure().GetReason(),
		one.GetClosure().GetClosedBy(), optional(one.GetClosure().GetClosedAt()),
		one.GetCorrelationKey(), int64(one.GetOccurrences()),
		one.GetFirstSeen().AsTime(), one.GetLastSeen().AsTime(),
	}
}

func trail(line *alertv1.Transition) []any {
	return []any{
		line.GetAlertId(), int64(line.GetRevision()),
		state(line.GetFrom()), state(line.GetTo()),
		line.GetAssignee(), line.GetActor(), line.GetAt().AsTime(), line.GetNote(),
	}
}

func restore(row pgx.CollectableRow) (*alertv1.Alert, error) {
	var (
		one                                     alertv1.Alert
		schemaVersion                           int32
		ruleID, ruleName, catalogue, identifier string
		ruleRevision, revision                  int64
		severity, class, named                  string
		tactic, techniqueID, techniqueName      string
		eventTime, closedAt                     *time.Time
		raisedAt, changedAt                     time.Time
		closureState, reason, by                string
		correlationKey                          string
		occurrences                             int64
		firstSeen, lastSeen                     time.Time
	)

	if err := row.Scan(
		&one.AlertId, &schemaVersion, &one.TenantId, &one.DetectionId,
		&ruleID, &ruleRevision, &ruleName, &catalogue, &identifier,
		&severity, &tactic, &techniqueID, &techniqueName,
		&class, &one.AgentId, &eventTime, &raisedAt,
		&named, &one.Assignee, &one.ChangedBy, &changedAt, &revision,
		&closureState, &reason, &by, &closedAt,
		&correlationKey, &occurrences, &firstSeen, &lastSeen,
	); err != nil {
		return nil, err
	}

	one.SchemaVersion = uint32(schemaVersion)
	one.Rule = &detectionv1.Rule{Id: ruleID, Revision: uint32(ruleRevision), Name: ruleName}
	if catalogue != "" || identifier != "" {
		one.Rule.Source = &detectionv1.Source{Catalogue: catalogue, Identifier: identifier}
	}
	one.Severity = detectionv1.Severity(detectionv1.Severity_value[enum("SEVERITY_", severity)])
	if tactic != "" || techniqueID != "" || techniqueName != "" {
		one.Technique = &detectionv1.Technique{Tactic: tactic, Id: techniqueID, Name: techniqueName}
	}
	one.EventClass = eventv1.EventClass(eventv1.EventClass_value[enum("EVENT_CLASS_", class)])
	one.EventTime = instant(eventTime)
	one.RaisedAt = timestamppb.New(raisedAt.UTC())
	one.CorrelationKey = correlationKey
	one.Occurrences = uint64(occurrences)
	one.FirstSeen = timestamppb.New(firstSeen.UTC())
	one.LastSeen = timestamppb.New(lastSeen.UTC())
	one.State = alert.State(named).Wire()
	one.ChangedAt = timestamppb.New(changedAt.UTC())
	one.Revision = uint64(revision)
	if closureState != "" {
		one.Closure = &alertv1.Closure{
			State:    alert.State(closureState).Wire(),
			Reason:   reason,
			ClosedBy: by,
			ClosedAt: instant(closedAt),
		}
	}
	return &one, nil
}

func restoreTransition(row pgx.CollectableRow) (*alertv1.Transition, error) {
	var (
		line     alertv1.Transition
		revision int64
		from, to string
		at       time.Time
	)
	if err := row.Scan(&line.AlertId, &revision, &from, &to, &line.Assignee, &line.Actor, &at, &line.Note); err != nil {
		return nil, err
	}
	line.Revision = uint64(revision)
	line.From = alert.State(from).Wire()
	line.To = alert.State(to).Wire()
	line.At = timestamppb.New(at.UTC())
	return &line, nil
}

func state(value alertv1.State) string {
	named, known := alert.FromWire(value)
	if !known {
		return ""
	}
	return named.String()
}

func states(asked []alertv1.State) []string {
	named := make([]string, 0, len(asked))
	for _, one := range asked {
		if written := state(one); written != "" {
			named = append(named, written)
		}
	}
	return named
}

func severities(asked []detectionv1.Severity) []string {
	named := make([]string, 0, len(asked))
	for _, one := range asked {
		if written := alert.Severity(one); written != "" {
			named = append(named, written)
		}
	}
	return named
}

func enum(prefix, value string) string {
	if value == "" {
		return prefix + "UNSPECIFIED"
	}
	return prefix + strings.ToUpper(value)
}

func optional(value *timestamppb.Timestamp) *time.Time {
	if value == nil {
		return nil
	}
	at := value.AsTime().UTC()
	return &at
}

func instant(value *time.Time) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return timestamppb.New(value.UTC())
}

func encodeCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UnixMilli(), 10) + "." + id))
}

func decodeCursor(token string) (time.Time, string, error) {
	payload, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return time.Time{}, "", alert.ErrCursor
	}
	written, id, found := strings.Cut(string(payload), ".")
	if !found || id == "" {
		return time.Time{}, "", alert.ErrCursor
	}
	millis, err := strconv.ParseInt(written, 10, 64)
	if err != nil {
		return time.Time{}, "", alert.ErrCursor
	}
	return time.UnixMilli(millis).UTC(), id, nil
}
