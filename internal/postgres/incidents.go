package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

// The incident half of the relational store: the same pool, the same schema and
// a port of its own, because what raises a story and what raises a piece of
// work are different callers asking for different words.
type Incidents struct {
	store *Store
}

func (s *Store) Incidents() *Incidents { return &Incidents{store: s} }

const incidentColumns = `incident_id, schema_version, tenant_id, detection_id,
	rule_id, rule_revision, rule_name, rule_source_catalogue, rule_source_identifier, ruleset_id,
	severity, confidence, technique_tactic, technique_id, technique_name,
	event_class, agent_id,
	stage_name, stage_event_id, stage_event_time,
	group_field, group_value, group_absent,
	window_seconds, clock_spread_millis,
	first_event_time, last_event_time, raised_at,
	state, assignee, changed_by, changed_at, revision,
	closure_state, closure_reason, closure_by, closure_at`

var insertIncident = `INSERT INTO incidents (` + incidentColumns + `)
VALUES (` + placeholdersFor(incidentColumns) + `) ON CONFLICT (incident_id) DO NOTHING`

const insertIncidentTransition = `INSERT INTO incident_transitions
	(incident_id, revision, from_state, to_state, assignee, actor, at, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (incident_id, revision) DO NOTHING`

func placeholdersFor(columns string) string {
	written := make([]string, strings.Count(columns, ",")+1)
	for index := range written {
		written[index] = "$" + strconv.Itoa(index+1)
	}
	return strings.Join(written, ",")
}

// One transaction for the batch, so a batch is durable or it is not. An
// incident already opened is recognised rather than reopened, which is what
// lets the writer retry the whole thing until the store takes it.
func (i *Incidents) Open(ctx context.Context, stories []*incidentv1.Incident) ([]incident.Outcome, error) {
	outcomes := make([]incident.Outcome, len(stories))
	if len(stories) == 0 {
		return outcomes, nil
	}

	transaction, err := i.store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin opening %d incidents: %w", len(stories), err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	for index, one := range stories {
		tag, err := transaction.Exec(ctx, insertIncident, storedIncident(one)...)
		if err != nil {
			return nil, fmt.Errorf("open incident %s: %w", one.GetIncidentId(), err)
		}
		if tag.RowsAffected() == 0 {
			outcomes[index] = incident.OutcomeRepeated
			continue
		}
		if _, err := transaction.Exec(ctx, insertIncidentTransition, incidentTrail(incident.Raised(one))...); err != nil {
			return nil, fmt.Errorf("record how incident %s was opened: %w", one.GetIncidentId(), err)
		}
		outcomes[index] = incident.OutcomeRaised
	}

	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit %d opened incidents: %w", len(stories), err)
	}
	return outcomes, nil
}

func (i *Incidents) Incident(ctx context.Context, id string, tenants []string) (*incidentv1.Incident, error) {
	rows, err := i.store.pool.Query(ctx,
		"SELECT "+incidentColumns+" FROM incidents WHERE incident_id = $1 AND tenant_id = ANY($2)", id, tenants)
	if err != nil {
		return nil, fmt.Errorf("read incident %s: %w", id, err)
	}
	found, err := pgx.CollectRows(rows, restoreIncident)
	if err != nil {
		return nil, fmt.Errorf("read incident %s: %w", id, err)
	}
	if len(found) == 0 {
		return nil, incident.ErrUnknownIncident
	}
	return found[0], nil
}

func (i *Incidents) History(ctx context.Context, id string, tenants []string) (*incidentv1.History, error) {
	if _, err := i.Incident(ctx, id, tenants); err != nil {
		return nil, err
	}

	rows, err := i.store.pool.Query(ctx,
		`SELECT incident_id, revision, from_state, to_state, assignee, actor, at, note
		 FROM incident_transitions WHERE incident_id = $1 ORDER BY revision`, id)
	if err != nil {
		return nil, fmt.Errorf("read the trail of incident %s: %w", id, err)
	}
	carried, err := pgx.CollectRows(rows, restoreIncidentTransition)
	if err != nil {
		return nil, fmt.Errorf("read the trail of incident %s: %w", id, err)
	}
	return &incidentv1.History{IncidentId: id, Transitions: carried}, nil
}

// The scope is a predicate on every read and is never composed from the cursor,
// so a position lifted from another caller's page still answers within the
// tenants this caller holds.
func (i *Incidents) Page(ctx context.Context, asked *incidentv1.Query, tenants []string) (*incidentv1.Page, error) {
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
	if named := incidentStates(asked.GetStates()); len(named) > 0 {
		where = append(where, "state = ANY("+place(named)+")")
	}
	if named := incidentSeverities(asked.GetSeverities()); len(named) > 0 {
		where = append(where, "severity = ANY("+place(named)+")")
	}
	if named := levels(asked.GetConfidences()); len(named) > 0 {
		where = append(where, "confidence = ANY("+place(named)+")")
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
		at, id, err := decodeIncidentCursor(asked.GetCursor())
		if err != nil {
			return nil, err
		}
		where = append(where, "(raised_at, incident_id) < ("+place(at)+", "+place(id)+")")
	}

	query := "SELECT " + incidentColumns + " FROM incidents WHERE " + strings.Join(where, " AND ") +
		" ORDER BY raised_at DESC, incident_id DESC LIMIT " + place(limit+1)

	rows, err := i.store.pool.Query(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	found, err := pgx.CollectRows(rows, restoreIncident)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}

	page := &incidentv1.Page{Incidents: found}
	if len(found) > limit {
		page.Incidents = found[:limit]
		last := page.Incidents[limit-1]
		page.NextCursor = encodeCursor(last.GetRaisedAt().AsTime(), last.GetIncidentId())
	}
	return page, nil
}

// Read, decide and write in one transaction with the row held, so the state the
// move was decided against is the state it is applied to. The story itself is
// never in the update: an operator moves the incident and what it is made of
// stays exactly as the analysis engine wrote it.
func (i *Incidents) Move(ctx context.Context, id string, tenants []string, asked incident.Move) (*incidentv1.Incident, error) {
	transaction, err := i.store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin moving incident %s: %w", id, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	rows, err := transaction.Query(ctx,
		"SELECT "+incidentColumns+" FROM incidents WHERE incident_id = $1 AND tenant_id = ANY($2) FOR UPDATE", id, tenants)
	if err != nil {
		return nil, fmt.Errorf("read incident %s: %w", id, err)
	}
	held, err := pgx.CollectRows(rows, restoreIncident)
	if err != nil {
		return nil, fmt.Errorf("read incident %s: %w", id, err)
	}
	if len(held) == 0 {
		return nil, incident.ErrUnknownIncident
	}

	moved, line, err := incident.Apply(held[0], asked)
	if err != nil {
		return nil, err
	}

	if _, err := transaction.Exec(ctx,
		`UPDATE incidents SET state = $2, assignee = $3, changed_by = $4, changed_at = $5, revision = $6,
			closure_state = $7, closure_reason = $8, closure_by = $9, closure_at = $10
		 WHERE incident_id = $1`,
		moved.GetIncidentId(),
		incidentState(moved.GetState()), moved.GetAssignee(), moved.GetChangedBy(),
		moved.GetChangedAt().AsTime(), int64(moved.GetRevision()),
		incidentState(moved.GetClosure().GetState()), moved.GetClosure().GetReason(),
		moved.GetClosure().GetClosedBy(), optional(moved.GetClosure().GetClosedAt()),
	); err != nil {
		return nil, fmt.Errorf("move incident %s: %w", id, err)
	}
	if _, err := transaction.Exec(ctx, insertIncidentTransition, incidentTrail(line)...); err != nil {
		return nil, fmt.Errorf("record the move of incident %s: %w", id, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit the move of incident %s: %w", id, err)
	}
	return moved, nil
}

func storedIncident(one *incidentv1.Incident) []any {
	names, events, times := stages(one.GetStages())
	fields, values, absent := groupings(one.GetGroup())

	return []any{
		one.GetIncidentId(), int32(one.GetSchemaVersion()), one.GetTenantId(), one.GetDetectionId(),
		one.GetRule().GetId(), int64(one.GetRule().GetRevision()), one.GetRule().GetName(),
		one.GetRule().GetSource().GetCatalogue(), one.GetRule().GetSource().GetIdentifier(), one.GetRulesetId(),
		incident.Severity(one.GetSeverity()), incident.Level(one.GetConfidence()),
		one.GetTechnique().GetTactic(), one.GetTechnique().GetId(), one.GetTechnique().GetName(),
		incident.Class(one.GetEventClass()), one.GetAgentId(),
		names, events, times,
		fields, values, absent,
		int64(one.GetWindow().AsDuration() / time.Second),
		int64(one.GetClockSpread().AsDuration() / time.Millisecond),
		one.GetFirstEventTime().AsTime(), one.GetLastEventTime().AsTime(), one.GetRaisedAt().AsTime(),
		incidentState(one.GetState()), one.GetAssignee(), one.GetChangedBy(),
		one.GetChangedAt().AsTime(), int64(one.GetRevision()),
		incidentState(one.GetClosure().GetState()), one.GetClosure().GetReason(),
		one.GetClosure().GetClosedBy(), optional(one.GetClosure().GetClosedAt()),
	}
}

func stages(told []*detectionv1.Stage) ([]string, []string, []time.Time) {
	names := make([]string, 0, len(told))
	events := make([]string, 0, len(told))
	times := make([]time.Time, 0, len(told))
	for _, stage := range told {
		names = append(names, stage.GetName())
		events = append(events, stage.GetEventId())
		times = append(times, stage.GetEventTime().AsTime().UTC())
	}
	return names, events, times
}

func groupings(group []*detectionv1.Grouping) ([]string, []string, []bool) {
	fields := make([]string, 0, len(group))
	values := make([]string, 0, len(group))
	absent := make([]bool, 0, len(group))
	for _, one := range group {
		fields = append(fields, one.GetField())
		values = append(values, one.GetValue())
		absent = append(absent, one.GetAbsent())
	}
	return fields, values, absent
}

func incidentTrail(line *incidentv1.Transition) []any {
	return []any{
		line.GetIncidentId(), int64(line.GetRevision()),
		incidentState(line.GetFrom()), incidentState(line.GetTo()),
		line.GetAssignee(), line.GetActor(), line.GetAt().AsTime(), line.GetNote(),
	}
}

func restoreIncident(row pgx.CollectableRow) (*incidentv1.Incident, error) {
	var (
		one                                     incidentv1.Incident
		schemaVersion                           int32
		ruleID, ruleName, catalogue, identifier string
		ruleRevision, revision                  int64
		severity, confidence, class, named      string
		tactic, techniqueID, techniqueName      string
		stageName, stageEvent                   []string
		stageTime                               []time.Time
		groupField, groupValue                  []string
		groupAbsent                             []bool
		windowSeconds, spreadMillis             int64
		firstEvent, lastEvent, raisedAt         time.Time
		changedAt                               time.Time
		closureState, reason, by                string
		closedAt                                *time.Time
	)

	if err := row.Scan(
		&one.IncidentId, &schemaVersion, &one.TenantId, &one.DetectionId,
		&ruleID, &ruleRevision, &ruleName, &catalogue, &identifier, &one.RulesetId,
		&severity, &confidence, &tactic, &techniqueID, &techniqueName,
		&class, &one.AgentId,
		&stageName, &stageEvent, &stageTime,
		&groupField, &groupValue, &groupAbsent,
		&windowSeconds, &spreadMillis,
		&firstEvent, &lastEvent, &raisedAt,
		&named, &one.Assignee, &one.ChangedBy, &changedAt, &revision,
		&closureState, &reason, &by, &closedAt,
	); err != nil {
		return nil, err
	}

	one.SchemaVersion = uint32(schemaVersion)
	one.Rule = &detectionv1.Rule{Id: ruleID, Revision: uint32(ruleRevision), Name: ruleName}
	if catalogue != "" || identifier != "" {
		one.Rule.Source = &detectionv1.Source{Catalogue: catalogue, Identifier: identifier}
	}
	one.Severity = detectionv1.Severity(detectionv1.Severity_value[enum("SEVERITY_", severity)])
	one.Confidence = incidentv1.Confidence(incidentv1.Confidence_value[enum("CONFIDENCE_", confidence)])
	if tactic != "" || techniqueID != "" || techniqueName != "" {
		one.Technique = &detectionv1.Technique{Tactic: tactic, Id: techniqueID, Name: techniqueName}
	}
	one.EventClass = eventv1.EventClass(eventv1.EventClass_value[enum("EVENT_CLASS_", class)])
	one.Stages = restoreStages(stageName, stageEvent, stageTime)
	one.Group = restoreGroupings(groupField, groupValue, groupAbsent)
	one.Window = durationpb.New(time.Duration(windowSeconds) * time.Second)
	one.ClockSpread = durationpb.New(time.Duration(spreadMillis) * time.Millisecond)
	one.FirstEventTime = timestamppb.New(firstEvent.UTC())
	one.LastEventTime = timestamppb.New(lastEvent.UTC())
	one.RaisedAt = timestamppb.New(raisedAt.UTC())
	one.State = incident.State(named).Wire()
	one.ChangedAt = timestamppb.New(changedAt.UTC())
	one.Revision = uint64(revision)
	if closureState != "" {
		one.Closure = &incidentv1.Closure{
			State:    incident.State(closureState).Wire(),
			Reason:   reason,
			ClosedBy: by,
			ClosedAt: instant(closedAt),
		}
	}
	return &one, nil
}

func restoreStages(names, events []string, times []time.Time) []*detectionv1.Stage {
	told := make([]*detectionv1.Stage, 0, len(names))
	for index := range names {
		if index >= len(events) || index >= len(times) {
			break
		}
		told = append(told, &detectionv1.Stage{
			Name:      names[index],
			EventId:   events[index],
			EventTime: timestamppb.New(times[index].UTC()),
		})
	}
	return told
}

func restoreGroupings(fields, values []string, absent []bool) []*detectionv1.Grouping {
	group := make([]*detectionv1.Grouping, 0, len(fields))
	for index := range fields {
		if index >= len(values) || index >= len(absent) {
			break
		}
		group = append(group, &detectionv1.Grouping{
			Field: fields[index], Value: values[index], Absent: absent[index],
		})
	}
	return group
}

func restoreIncidentTransition(row pgx.CollectableRow) (*incidentv1.Transition, error) {
	var (
		line     incidentv1.Transition
		revision int64
		from, to string
		at       time.Time
	)
	if err := row.Scan(&line.IncidentId, &revision, &from, &to, &line.Assignee, &line.Actor, &at, &line.Note); err != nil {
		return nil, err
	}
	line.Revision = uint64(revision)
	line.From = incident.State(from).Wire()
	line.To = incident.State(to).Wire()
	line.At = timestamppb.New(at.UTC())
	return &line, nil
}

func incidentState(value incidentv1.State) string {
	named, known := incident.FromWire(value)
	if !known {
		return ""
	}
	return named.String()
}

func incidentStates(asked []incidentv1.State) []string {
	named := make([]string, 0, len(asked))
	for _, one := range asked {
		if written := incidentState(one); written != "" {
			named = append(named, written)
		}
	}
	return named
}

func incidentSeverities(asked []detectionv1.Severity) []string {
	named := make([]string, 0, len(asked))
	for _, one := range asked {
		if written := incident.Severity(one); written != "" {
			named = append(named, written)
		}
	}
	return named
}

func levels(asked []incidentv1.Confidence) []string {
	named := make([]string, 0, len(asked))
	for _, one := range asked {
		if written := incident.Level(one); written != "" {
			named = append(named, written)
		}
	}
	return named
}

func decodeIncidentCursor(token string) (time.Time, string, error) {
	at, id, err := decodeCursor(token)
	if err != nil {
		return time.Time{}, "", incident.ErrCursor
	}
	return at, id, nil
}
