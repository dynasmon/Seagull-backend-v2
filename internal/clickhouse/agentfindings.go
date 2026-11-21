package clickhouse

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentfindingstore"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const (
	agentFindingsTable = "agent_findings"

	DefaultFindingPage = 50
	MaxFindingPage     = 500
	MaxOpenPerAgent    = 32
)

// The writer and the final migrated schema must name columns in the same order.
var agentFindingColumns = []string{
	"tenant_id",
	"agent_id",
	"finding_id",

	"kind",
	"state",
	"closure",

	"opened_at",
	"last_observed_at",
	"observations",
	"closed_at",
	"decided_at",

	"finding",
}

func agentFindingValues(row agentfindingstore.Row) []any {
	return []any{
		row.TenantID,
		row.AgentID,
		row.FindingID,

		row.Kind,
		row.State,
		row.Closure,

		row.OpenedAt,
		row.LastObservedAt,
		row.Observations,
		row.ClosedAt,
		row.DecidedAt,

		string(row.Finding),
	}
}

type AgentFindingStore struct {
	connection driver.Conn
	database   string
	insert     string
}

func NewAgentFindingStore(configuration Config) (*AgentFindingStore, error) {
	if err := agentFindingsAgreeWithSchema(); err != nil {
		return nil, err
	}
	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}
	return &AgentFindingStore{
		connection: connection,
		database:   configuration.Database,
		insert:     fmt.Sprintf("INSERT INTO %s (%s)", agentFindingsTable, strings.Join(agentFindingColumns, ", ")),
	}, nil
}

func (s *AgentFindingStore) Store(ctx context.Context, rows []agentfindingstore.Row) error {
	if len(rows) == 0 {
		return nil
	}
	batch, err := s.connection.PrepareBatch(ctx, s.insert)
	if err != nil {
		return fmt.Errorf("open a batch on %s: %w", agentFindingsTable, err)
	}
	for _, row := range rows {
		if err := batch.Append(agentFindingValues(row)...); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("add finding %s of agent %s to the batch: %w", row.FindingID, row.AgentID, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("write %d rows to %s: %w", len(rows), agentFindingsTable, err)
	}
	return nil
}

func (s *AgentFindingStore) Ping(ctx context.Context) error {
	if err := s.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the agent finding store: %w", err)
	}
	return nil
}

func (s *AgentFindingStore) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, s.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		names := make([]string, 0, len(outstanding))
		for _, entry := range outstanding {
			names = append(names, entry.String())
		}
		return fmt.Errorf("the agent finding store is missing %d migration(s): %s — run store-migrator",
			len(outstanding), strings.Join(names, ", "))
	}
	return columnsPresent(ctx, s.connection, s.database, agentFindingsTable, agentFindingColumns)
}

func (s *AgentFindingStore) Close() error { return s.connection.Close() }

func agentFindingsAgreeWithSchema() error {
	declared, err := declaredColumns(agentFindingsTable)
	if err != nil {
		return err
	}
	if !slices.Equal(declared, agentFindingColumns) {
		return fmt.Errorf("the store writes %d columns of %s and the migrated schema defines %d: %s versus %s",
			len(agentFindingColumns), agentFindingsTable, len(declared), strings.Join(agentFindingColumns, ", "), strings.Join(declared, ", "))
	}
	if values := len(agentFindingValues(agentfindingstore.Row{})); values != len(agentFindingColumns) {
		return fmt.Errorf("the store names %d columns of %s and supplies %d values", len(agentFindingColumns), agentFindingsTable, values)
	}
	return nil
}

// The open findings of each agent asked about, newest first and at most
// MaxOpenPerAgent of each, bounded by the agents of one read and the tenants the
// caller holds. A decision this build cannot read is left out.
func (s *AgentFindingStore) Open(ctx context.Context, agents, tenants []string) (map[string][]*agentv1.Finding, error) {
	if len(agents) == 0 || len(tenants) == 0 {
		return map[string][]*agentv1.Finding{}, nil
	}
	where, arguments := scopedTo(agents, tenants)
	arguments = append(arguments, agentfinding.StateName(agentv1.Finding_STATE_OPEN))
	rows, err := s.connection.Query(ctx,
		"SELECT agent_id, finding FROM "+agentFindingsTable+" FINAL"+where+" AND state = ?"+
			" ORDER BY opened_at DESC, finding_id DESC LIMIT "+strconv.Itoa(MaxOpenPerAgent)+" BY agent_id",
		arguments...)
	if err != nil {
		return nil, fmt.Errorf("read the open findings of agents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	open := make(map[string][]*agentv1.Finding, len(agents))
	for rows.Next() {
		var id, body string
		if err := rows.Scan(&id, &body); err != nil {
			return nil, fmt.Errorf("read the open findings of agents: %w", err)
		}
		var decided agentv1.Finding
		if err := proto.Unmarshal([]byte(body), &decided); err != nil {
			continue
		}
		open[id] = append(open[id], &decided)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the open findings of agents: %w", err)
	}
	return open, nil
}

// One page of the findings about the agents of the tenants the caller holds,
// newest opened first. The cursor carries the instant and the identifier of the
// last finding of the page, to the millisecond the store keeps.
func (s *AgentFindingStore) Search(ctx context.Context, asked *agentv1.FindingQuery, tenants []string) (*agentv1.FindingPage, error) {
	if len(tenants) == 0 {
		return &agentv1.FindingPage{}, nil
	}
	limit := int(asked.GetLimit())
	if limit <= 0 {
		limit = DefaultFindingPage
	}
	limit = min(limit, MaxFindingPage)

	conditions := []string{"tenant_id IN (" + placeholders(len(tenants)) + ")"}
	arguments := make([]any, 0, len(tenants)+16)
	for _, tenant := range tenants {
		arguments = append(arguments, tenant)
	}
	if agentID := asked.GetAgentId(); agentID != "" {
		conditions, arguments = append(conditions, "agent_id = ?"), append(arguments, agentID)
	}
	if kinds := asked.GetKinds(); len(kinds) > 0 {
		conditions = append(conditions, "kind IN ("+placeholders(len(kinds))+")")
		for _, kind := range kinds {
			arguments = append(arguments, agentfinding.KindName(kind))
		}
	}
	if states := asked.GetStates(); len(states) > 0 {
		conditions = append(conditions, "state IN ("+placeholders(len(states))+")")
		for _, state := range states {
			arguments = append(arguments, agentfinding.StateName(state))
		}
	}
	if from := asked.GetRange().GetStart(); from != nil {
		conditions, arguments = append(conditions, "opened_at >= "+instantPlaceholder), append(arguments, from.AsTime().UnixMilli())
	}
	if to := asked.GetRange().GetEnd(); to != nil {
		conditions, arguments = append(conditions, "opened_at < "+instantPlaceholder), append(arguments, to.AsTime().UnixMilli())
	}
	if cursor := asked.GetCursor(); cursor != "" {
		at, id, err := decodeFindingCursor(cursor)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, "(opened_at < "+instantPlaceholder+" OR (opened_at = "+instantPlaceholder+" AND finding_id < ?))")
		arguments = append(arguments, at, at, id)
	}

	rows, err := s.connection.Query(ctx,
		"SELECT opened_at, finding_id, finding FROM "+agentFindingsTable+" FINAL"+
			" WHERE "+strings.Join(conditions, " AND ")+
			" ORDER BY opened_at DESC, finding_id DESC LIMIT "+strconv.Itoa(limit+1),
		arguments...)
	if err != nil {
		return nil, fmt.Errorf("search the findings about agents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	page := &agentv1.FindingPage{}
	var lastAt time.Time
	var lastID string
	for rows.Next() {
		var (
			at       time.Time
			id, body string
		)
		if err := rows.Scan(&at, &id, &body); err != nil {
			return nil, fmt.Errorf("search the findings about agents: %w", err)
		}
		if len(page.Findings) == limit {
			page.NextCursor = encodeFindingCursor(lastAt, lastID)
			break
		}
		lastAt, lastID = at, id
		var decided agentv1.Finding
		if err := proto.Unmarshal([]byte(body), &decided); err != nil {
			continue
		}
		page.Findings = append(page.Findings, &decided)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("search the findings about agents: %w", err)
	}
	return page, nil
}

// How many findings are open, by kind, across every tenant: what the fleet count
// publishes beside liveness, never by agent and never by tenant.
func (s *AgentFindingStore) CountOpen(ctx context.Context) (map[string]int, error) {
	rows, err := s.connection.Query(ctx,
		"SELECT kind, count() FROM "+agentFindingsTable+" FINAL WHERE state = ? GROUP BY kind",
		agentfinding.StateName(agentv1.Finding_STATE_OPEN))
	if err != nil {
		return nil, fmt.Errorf("count the open findings about agents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	counted := map[string]int{}
	for rows.Next() {
		var (
			kind  string
			count uint64
		)
		if err := rows.Scan(&kind, &count); err != nil {
			return nil, fmt.Errorf("count the open findings about agents: %w", err)
		}
		counted[kind] = int(count)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("count the open findings about agents: %w", err)
	}
	return counted, nil
}

func encodeFindingCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UnixMilli(), 10) + "|" + id))
}

func decodeFindingCursor(cursor string) (int64, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, "", agentfinding.ErrCursor
	}
	millis, id, found := strings.Cut(string(raw), "|")
	at, err := strconv.ParseInt(millis, 10, 64)
	if !found || err != nil || len(id) != agentfinding.IDLength {
		return 0, "", agentfinding.ErrCursor
	}
	return at, id, nil
}
