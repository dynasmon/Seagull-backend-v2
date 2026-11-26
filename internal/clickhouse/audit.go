package clickhouse

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/internal/auditstore"
)

const (
	auditEntriesTable = "audit_entries"

	// What one read names at most, so a batch of any size the writer may be
	// configured with reads in statements well inside the store's query size.
	auditReadWidth = 128
)

// The writer and the final migrated schema must name columns in the same order.
var auditEntryColumns = []string{
	"chain",
	"sequence",
	"previous",
	"digest",

	"event_id",
	"occurred_at",
	"action",
	"actor_subject",
	"target_id",

	"log_partition",
	"log_offset",

	"event",
}

func auditEntryValues(row auditstore.Row) []any {
	return []any{
		row.Chain,
		row.Sequence,
		row.Previous,
		row.Digest,

		row.EventID,
		row.OccurredAt,
		row.Action,
		row.ActorSubject,
		row.TargetID,

		row.LogPartition,
		row.LogOffset,

		string(row.Event),
	}
}

// The audit trail as the one process that chains it reaches it: the only adapter
// that inserts into it, reading back no more than chaining needs.
type AuditStore struct {
	connection driver.Conn
	database   string
	insert     string
}

func NewAuditStore(configuration Config) (*AuditStore, error) {
	if err := auditEntriesAgreeWithSchema(); err != nil {
		return nil, err
	}
	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}
	return &AuditStore{
		connection: connection,
		database:   configuration.Database,
		insert:     fmt.Sprintf("INSERT INTO %s (%s)", auditEntriesTable, strings.Join(auditEntryColumns, ", ")),
	}, nil
}

func (s *AuditStore) Append(ctx context.Context, rows []auditstore.Row) error {
	if len(rows) == 0 {
		return nil
	}
	batch, err := s.connection.PrepareBatch(ctx, s.insert)
	if err != nil {
		return fmt.Errorf("open a batch on %s: %w", auditEntriesTable, err)
	}
	for _, row := range rows {
		if err := batch.Append(auditEntryValues(row)...); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("add entry %d of a chain to the batch: %w", row.Sequence, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("write %d rows to %s: %w", len(rows), auditEntriesTable, err)
	}
	return nil
}

func (s *AuditStore) Chained(ctx context.Context, asked map[string][]string) (map[string]map[string]uint64, error) {
	type pair struct{ chain, identifier string }
	var pairs []pair
	for _, chain := range slices.Sorted(maps.Keys(asked)) {
		identifiers := slices.Clone(asked[chain])
		slices.Sort(identifiers)
		for _, identifier := range slices.Compact(identifiers) {
			pairs = append(pairs, pair{chain: chain, identifier: identifier})
		}
	}

	held := map[string]map[string]uint64{}
	for chunk := range slices.Chunk(pairs, auditReadWidth) {
		var chains, identifiers []string
		for _, one := range chunk {
			chains = append(chains, one.chain)
			identifiers = append(identifiers, one.identifier)
		}
		slices.Sort(identifiers)
		chains, identifiers = slices.Compact(chains), slices.Compact(identifiers)
		if err := s.chained(ctx, chains, identifiers, asked, held); err != nil {
			return nil, err
		}
	}
	return held, nil
}

func (s *AuditStore) chained(ctx context.Context, chains, identifiers []string, asked map[string][]string, held map[string]map[string]uint64) error {
	arguments := make([]any, 0, len(chains)+len(identifiers))
	for _, chain := range chains {
		arguments = append(arguments, chain)
	}
	for _, identifier := range identifiers {
		arguments = append(arguments, identifier)
	}
	rows, err := s.connection.Query(ctx,
		"SELECT chain, event_id, min(sequence) FROM "+auditEntriesTable+
			" WHERE chain IN ("+placeholders(len(chains))+") AND event_id IN ("+placeholders(len(identifiers))+")"+
			" GROUP BY chain, event_id",
		arguments...)
	if err != nil {
		return fmt.Errorf("read which events the audit chains hold: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			chain, identifier string
			sequence          uint64
		)
		if err := rows.Scan(&chain, &identifier, &sequence); err != nil {
			return fmt.Errorf("read which events the audit chains hold: %w", err)
		}
		if !slices.Contains(asked[chain], identifier) {
			continue
		}
		if held[chain] == nil {
			held[chain] = map[string]uint64{}
		}
		if known, found := held[chain][identifier]; !found || sequence < known {
			held[chain][identifier] = sequence
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read which events the audit chains hold: %w", err)
	}
	return nil
}

// One read per chain, each fixing the chain so the store reads the end of it
// backwards along its sorting key instead of the whole chain. Two rows at the
// newest sequence that differ are resolved by the smaller digest, so every
// writer continues the chain from the same one.
func (s *AuditStore) Heads(ctx context.Context, chains []string) (map[string]auditstore.Head, error) {
	heads := make(map[string]auditstore.Head, len(chains))
	for chunk := range slices.Chunk(chains, auditReadWidth) {
		if err := s.heads(ctx, chunk, heads); err != nil {
			return nil, err
		}
	}
	return heads, nil
}

func (s *AuditStore) heads(ctx context.Context, chains []string, heads map[string]auditstore.Head) error {
	reads := make([]string, 0, len(chains))
	arguments := make([]any, 0, len(chains))
	for _, chain := range chains {
		reads = append(reads, "(SELECT chain, sequence, digest, log_partition, log_offset FROM "+auditEntriesTable+
			" WHERE chain = ? ORDER BY sequence DESC, digest LIMIT 1)")
		arguments = append(arguments, chain)
	}
	rows, err := s.connection.Query(ctx, strings.Join(reads, " UNION ALL "), arguments...)
	if err != nil {
		return fmt.Errorf("read where the audit chains stand: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			chain, digest string
			head          auditstore.Head
		)
		if err := rows.Scan(&chain, &head.Sequence, &digest, &head.Partition, &head.Offset); err != nil {
			return fmt.Errorf("read where the audit chains stand: %w", err)
		}
		head.Digest = []byte(digest)
		heads[chain] = head
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read where the audit chains stand: %w", err)
	}
	return nil
}

func (s *AuditStore) Ping(ctx context.Context) error {
	if err := s.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the audit store: %w", err)
	}
	return nil
}

func (s *AuditStore) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, s.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		names := make([]string, 0, len(outstanding))
		for _, entry := range outstanding {
			names = append(names, entry.String())
		}
		return fmt.Errorf("the audit store is missing %d migration(s): %s — run store-migrator",
			len(outstanding), strings.Join(names, ", "))
	}
	return columnsPresent(ctx, s.connection, s.database, auditEntriesTable, auditEntryColumns)
}

func (s *AuditStore) Close() error { return s.connection.Close() }

func auditEntriesAgreeWithSchema() error {
	declared, err := declaredColumns(auditEntriesTable)
	if err != nil {
		return err
	}
	if !slices.Equal(declared, auditEntryColumns) {
		return fmt.Errorf("the store writes %d columns of %s and the migrated schema defines %d: %s versus %s",
			len(auditEntryColumns), auditEntriesTable, len(declared), strings.Join(auditEntryColumns, ", "), strings.Join(declared, ", "))
	}
	if values := len(auditEntryValues(auditstore.Row{})); values != len(auditEntryColumns) {
		return fmt.Errorf("the store names %d columns of %s and supplies %d values", len(auditEntryColumns), auditEntriesTable, values)
	}
	return nil
}
