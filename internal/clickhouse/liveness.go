package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const DefaultLivenessHorizon = 30 * 24 * time.Hour

// When telemetry from an agent last reached the platform. It is a read of the
// analytical store and not of the registry: an agent's administrative record
// says what was decided about it, and whether it is still talking is a fact
// about the stream.
type Liveness struct {
	connection driver.Conn
	horizon    time.Duration
}

func NewLiveness(configuration Config, horizon time.Duration) (*Liveness, error) {
	if horizon <= 0 {
		return nil, errors.New("a liveness reader needs a positive horizon to look back over")
	}
	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}
	return &Liveness{connection: connection, horizon: horizon}, nil
}

// Bounded three ways — the agents asked about, the tenants the caller holds and
// how far back to look — so reading an agent list can never turn into a scan of
// everything the platform ever collected. `ingest_time` is the platform's clock
// and not the producer's, which is what stops an agent backdating itself alive.
func (l *Liveness) LastSeen(ctx context.Context, agents, tenants []string) (map[string]time.Time, error) {
	if len(agents) == 0 || len(tenants) == 0 {
		return map[string]time.Time{}, nil
	}

	arguments := make([]any, 0, len(tenants)+len(agents)+1)
	for _, tenant := range tenants {
		arguments = append(arguments, tenant)
	}
	for _, agentID := range agents {
		arguments = append(arguments, agentID)
	}
	arguments = append(arguments, time.Now().Add(-l.horizon).UnixMilli())

	rows, err := l.connection.Query(ctx,
		"SELECT agent_id, max(ingest_time) FROM "+table+
			" WHERE tenant_id IN ("+placeholders(len(tenants))+")"+
			" AND agent_id IN ("+placeholders(len(agents))+")"+
			" AND event_time >= "+instantPlaceholder+
			" GROUP BY agent_id",
		arguments...)
	if err != nil {
		return nil, fmt.Errorf("read when agents were last seen: %w", err)
	}
	defer func() { _ = rows.Close() }()

	seen := make(map[string]time.Time, len(agents))
	for rows.Next() {
		var (
			agentID string
			at      time.Time
		)
		if err := rows.Scan(&agentID, &at); err != nil {
			return nil, fmt.Errorf("read when agents were last seen: %w", err)
		}
		seen[agentID] = at.UTC()
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read when agents were last seen: %w", err)
	}
	return seen, nil
}

func (l *Liveness) Ping(ctx context.Context) error {
	if err := l.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the store: %w", err)
	}
	return nil
}

func (l *Liveness) Close() error { return l.connection.Close() }
