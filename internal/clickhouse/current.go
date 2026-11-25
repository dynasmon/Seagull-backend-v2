package clickhouse

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// The newest full enumeration of one kind on one asset: the line absence is
// measured against, and how old the answer for that kind is.
type enumeration struct {
	scannedAt time.Time
	recordID  string
	items     uint32
}

func enumerations(ctx context.Context, connection driver.Conn, tenants []string, agent string, kinds []string) (map[string]enumeration, error) {
	arguments := make([]any, 0, len(tenants)+len(kinds)+1)
	for _, tenant := range tenants {
		arguments = append(arguments, tenant)
	}
	arguments = append(arguments, agent)
	for _, kind := range kinds {
		arguments = append(arguments, kind)
	}
	rows, err := connection.Query(ctx, "SELECT kind, max(scanned_at), argMax(record_id, scanned_at), argMax(items, scanned_at) FROM "+scanTable+
		" WHERE tenant_id IN ("+placeholders(len(tenants))+") AND agent_id = ? AND kind IN ("+placeholders(len(kinds))+") GROUP BY kind", arguments...)
	if err != nil {
		return nil, fmt.Errorf("read the scans of agent %s: %w", agent, err)
	}
	lines := map[string]enumeration{}
	for rows.Next() {
		var kind string
		var line enumeration
		if err := rows.Scan(&kind, &line.scannedAt, &line.recordID, &line.items); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read a scan of agent %s: %w", agent, err)
		}
		line.scannedAt = line.scannedAt.UTC()
		lines[kind] = line
	}
	if err := closed(rows); err != nil {
		return nil, fmt.Errorf("read the scans of agent %s: %w", agent, err)
	}
	return lines, nil
}

// What an asset currently has, the one place it is written (ADR 27): an item
// last seen at or after the newest full enumeration of its kind, and every item
// of a kind never enumerated in full, since only a full enumeration says what is
// gone. Reading a kind nobody enumerated as empty would close every finding on
// it for a gap and report what a delta named for too short a time rather than
// too long (ADR 43, 49). The matcher and the read plane both ask through this.
func currentAgainst(kinds []string, enumerated map[string]enumeration) (string, []any) {
	terms := make([]string, 0, len(kinds))
	arguments := make([]any, 0, 2*len(kinds))
	for _, kind := range kinds {
		if line, scanned := enumerated[kind]; scanned {
			terms = append(terms, "(kind = ? AND last_seen >= "+instantPlaceholder+")")
			arguments = append(arguments, kind, line.scannedAt.UnixMilli())
			continue
		}
		terms = append(terms, "kind = ?")
		arguments = append(arguments, kind)
	}
	return "(" + strings.Join(terms, " OR ") + ")", arguments
}
