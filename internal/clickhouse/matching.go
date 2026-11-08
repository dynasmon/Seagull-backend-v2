package clickhouse

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/finding"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/matching"
	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// What the vulnerability matcher reads, over a connection of its own that a
// deployment gives a credential able to read and nothing more. It holds no
// insert statement, so nothing it decides reaches a store except through the
// findings stream and the writer that owns that store.
type MatchingReader struct {
	connection driver.Conn
	database   string
}

func NewMatchingReader(configuration Config) (*MatchingReader, error) {
	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}
	return &MatchingReader{connection: connection, database: configuration.Database}, nil
}

var matchingReads = map[string][]string{
	inventoryTable: {"tenant_id", "agent_id", "kind", "item_id", "record_id", "last_seen",
		"os_name", "os_version", "os_build", "os_platform", "os_codename", "os_family",
		"package_name", "package_version", "package_architecture", "package_manager",
		"package_source", "package_vendor", "package_size_bytes", "package_installed_at"},
	scanTable:   {"tenant_id", "agent_id", "kind", "scanned_at", "record_id"},
	holderTable: {"package", "tenant_id", "agent_id"},
	affectedTable: {"ecosystem", "package", "source", "advisory_id", "modified", "normalization", "entry",
		"range_types", "event_ranges", "event_kinds", "event_versions", "versions",
		"severity_types", "severity_scores", "severity_assessors", "withdrawn"},
	advisoryTable: {"source", "advisory_id", "modified", "normalization", "aliases", "upstream",
		"severity_types", "severity_scores", "severity_assessors", "feed", "fetched_at"},
	feedSyncTable: {"source", "feed", "checked_at", "synced_at"},
	findingTable:  {"tenant_id", "agent_id", "item_id", "vulnerability_id", "inventory_as_of", "intelligence_as_of", "decided_at", "record"},
}

func (r *MatchingReader) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, r.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		return fmt.Errorf("the store the matcher reads is missing %d migration(s) — run store-migrator", len(outstanding))
	}
	for _, table := range slices.Sorted(func(yield func(string) bool) {
		for table := range matchingReads {
			if !yield(table) {
				return
			}
		}
	}) {
		if err := columnsPresent(ctx, r.connection, r.database, table, matchingReads[table]); err != nil {
			return err
		}
	}
	return nil
}

// Current is the inventory's own rule: an item at or after the newest full
// scan of its kind, or any item of a kind never scanned in full.
func (r *MatchingReader) Asset(ctx context.Context, asset matching.Asset) (finding.Asset, bool, error) {
	kinds := []any{asset.TenantID, asset.AgentID, packageKind, systemKind}
	lines := map[string]finding.Scan{}
	scans, err := r.connection.Query(ctx,
		"SELECT kind, max(scanned_at), argMax(record_id, scanned_at) FROM "+scanTable+
			" WHERE tenant_id = ? AND agent_id = ? AND kind IN (?, ?) GROUP BY kind", kinds...)
	if err != nil {
		return finding.Asset{}, false, fmt.Errorf("read the scans of agent %s: %w", asset.AgentID, err)
	}
	for scans.Next() {
		var kind string
		var line finding.Scan
		if err := scans.Scan(&kind, &line.ScannedAt, &line.RecordID); err != nil {
			_ = scans.Close()
			return finding.Asset{}, false, fmt.Errorf("read a scan of agent %s: %w", asset.AgentID, err)
		}
		line.ScannedAt = line.ScannedAt.UTC()
		lines[kind] = line
	}
	if err := closed(scans); err != nil {
		return finding.Asset{}, false, fmt.Errorf("read the scans of agent %s: %w", asset.AgentID, err)
	}

	rows, err := r.connection.Query(ctx, "SELECT kind, item_id, record_id, last_seen,"+
		" os_name, os_version, os_build, os_platform, os_codename, os_family,"+
		" package_name, package_version, package_architecture, package_manager, package_source, package_vendor, package_size_bytes, package_installed_at"+
		" FROM "+inventoryTable+" FINAL WHERE tenant_id = ? AND agent_id = ? AND kind IN (?, ?) ORDER BY kind, item_id", kinds...)
	if err != nil {
		return finding.Asset{}, false, fmt.Errorf("read the inventory of agent %s: %w", asset.AgentID, err)
	}
	held := finding.Asset{TenantID: asset.TenantID, AgentID: asset.AgentID, Scan: lines[packageKind]}
	found := false
	var newestSystem time.Time
	for rows.Next() {
		var kind string
		var item finding.Item
		system := &inventoryv1.OperatingSystem{}
		installed := &inventoryv1.Package{}
		var installedAt time.Time
		if err := rows.Scan(&kind, &item.ID, &item.RecordID, &item.LastSeen,
			&system.Name, &system.Version, &system.Build, &system.Platform, &system.Codename, &system.Family,
			&installed.Name, &installed.Version, &installed.Architecture, &installed.Manager, &installed.Source, &installed.Vendor, &installed.SizeBytes, &installedAt,
		); err != nil {
			_ = rows.Close()
			return finding.Asset{}, false, fmt.Errorf("read an item of agent %s: %w", asset.AgentID, err)
		}
		item.LastSeen = item.LastSeen.UTC()
		if line, scanned := lines[kind]; scanned && item.LastSeen.Before(line.ScannedAt) {
			continue
		}
		found = true
		held.AsOf = latest(held.AsOf, item.LastSeen)
		if kind == systemKind {
			if held.System == nil || item.LastSeen.After(newestSystem) {
				held.System, newestSystem = system, item.LastSeen
			}
			continue
		}
		if installedAt.After(time.Unix(0, 0)) {
			installed.InstalledAt = timestamppb.New(installedAt)
		}
		item.Package = installed
		held.Packages = append(held.Packages, item)
	}
	if err := closed(rows); err != nil {
		return finding.Asset{}, false, fmt.Errorf("read the inventory of agent %s: %w", asset.AgentID, err)
	}
	for _, line := range lines {
		held.AsOf = latest(held.AsOf, line.ScannedAt)
	}
	return held, found || len(lines) > 0, nil
}

func (r *MatchingReader) Holders(ctx context.Context, packages []string) ([]matching.Asset, error) {
	if len(packages) == 0 {
		return nil, nil
	}
	rows, err := r.connection.Query(ctx,
		"SELECT DISTINCT tenant_id, agent_id FROM "+holderTable+" WHERE package IN ("+placeholders(len(packages))+") ORDER BY tenant_id, agent_id",
		strings2any(packages)...)
	if err != nil {
		return nil, fmt.Errorf("read the holders of %d packages: %w", len(packages), err)
	}
	var holders []matching.Asset
	for rows.Next() {
		var holder matching.Asset
		if err := rows.Scan(&holder.TenantID, &holder.AgentID); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read a holder: %w", err)
		}
		holders = append(holders, holder)
	}
	return holders, closed(rows)
}

// The newest version of every advisory naming one of the packages in the
// ecosystem, read with the newest rules it was stored under, leaving out one
// that version withdrew: the definition the vulnerability store states.
func (r *MatchingReader) Read(ctx context.Context, ecosystem string, packages []string) (finding.Intelligence, error) {
	feed, err := vulnerability.FeedOf(ecosystem)
	if err != nil {
		return finding.Intelligence{}, err
	}
	intelligence := finding.Intelligence{Feed: finding.Feed{Name: feed}}
	if err := r.freshness(ctx, &intelligence); err != nil {
		return finding.Intelligence{}, err
	}
	if len(packages) == 0 {
		return intelligence, nil
	}

	named := strings2any(packages)
	arguments := append(append([]any{ecosystem}, named...), append([]any{ecosystem}, named...)...)
	rows, err := r.connection.Query(ctx, "SELECT entry.source, entry.advisory_id, entry.modified, entry.normalization, entry.package,"+
		" entry.range_types, entry.event_ranges, entry.event_kinds, entry.event_versions, entry.versions,"+
		" entry.severity_types, entry.severity_scores, entry.severity_assessors"+
		" FROM "+affectedTable+" AS entry FINAL"+
		" INNER JOIN (SELECT source, advisory_id, max((modified, normalization)) AS newest FROM "+advisoryTable+
		" WHERE (source, advisory_id) IN (SELECT source, advisory_id FROM "+affectedTable+
		" WHERE ecosystem = ? AND package IN ("+placeholders(len(packages))+")) GROUP BY source, advisory_id) AS version"+
		" ON entry.source = version.source AND entry.advisory_id = version.advisory_id"+
		" WHERE entry.ecosystem = ? AND entry.package IN ("+placeholders(len(packages))+")"+
		" AND (entry.modified, entry.normalization) = version.newest AND entry.withdrawn = toDateTime64(0, 3, 'UTC')"+
		" ORDER BY entry.source, entry.advisory_id, entry.entry", arguments...)
	if err != nil {
		return finding.Intelligence{}, fmt.Errorf("read the advisories of %s: %w", ecosystem, err)
	}
	byName := map[[2]string]*finding.Advisory{}
	var order [][2]string
	for rows.Next() {
		var (
			advisory                            finding.Advisory
			name                                string
			rangeTypes, kinds, versions, listed []string
			eventRanges                         []uint32
			types, scores, assessors            []string
		)
		if err := rows.Scan(&advisory.Source, &advisory.ID, &advisory.Modified, &advisory.Normalization, &name,
			&rangeTypes, &eventRanges, &kinds, &versions, &listed, &types, &scores, &assessors); err != nil {
			_ = rows.Close()
			return finding.Intelligence{}, fmt.Errorf("read an advisory of %s: %w", ecosystem, err)
		}
		entry, err := affectedOf(ecosystem, name, rangeTypes, eventRanges, kinds, versions, listed, severitiesOf(types, scores, assessors))
		if err != nil {
			_ = rows.Close()
			return finding.Intelligence{}, fmt.Errorf("read advisory %s: %w", advisory.ID, err)
		}
		key := [2]string{advisory.Source, advisory.ID}
		if byName[key] == nil {
			advisory.Modified = advisory.Modified.UTC()
			byName[key] = &advisory
			order = append(order, key)
		}
		byName[key].Affected = append(byName[key].Affected, entry)
	}
	if err := closed(rows); err != nil {
		return finding.Intelligence{}, fmt.Errorf("read the advisories of %s: %w", ecosystem, err)
	}
	if err := r.names(ctx, byName); err != nil {
		return finding.Intelligence{}, err
	}
	for _, key := range order {
		intelligence.Advisories = append(intelligence.Advisories, *byName[key])
	}
	return intelligence, nil
}

func (r *MatchingReader) names(ctx context.Context, advisories map[[2]string]*finding.Advisory) error {
	if len(advisories) == 0 {
		return nil
	}
	var tuples []string
	var arguments []any
	for _, advisory := range advisories {
		tuples = append(tuples, "(?, ?, "+versionPlaceholder+", ?)")
		arguments = append(arguments, advisory.Source, advisory.ID, advisory.Modified.UnixNano(), advisory.Normalization)
	}
	rows, err := r.connection.Query(ctx, "SELECT source, advisory_id, aliases, upstream, severity_types, severity_scores, severity_assessors FROM "+
		advisoryTable+" FINAL WHERE (source, advisory_id, modified, normalization) IN ("+strings.Join(tuples, ", ")+")", arguments...)
	if err != nil {
		return fmt.Errorf("read the names of %d advisories: %w", len(advisories), err)
	}
	for rows.Next() {
		var source, id string
		var aliases, upstream, types, scores, assessors []string
		if err := rows.Scan(&source, &id, &aliases, &upstream, &types, &scores, &assessors); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read the names of an advisory: %w", err)
		}
		if advisory := advisories[[2]string{source, id}]; advisory != nil {
			advisory.Aliases, advisory.Upstream, advisory.Severities = aliases, upstream, severitiesOf(types, scores, assessors)
		}
	}
	return closed(rows)
}

// A feed read by more than one source is as fresh as the stalest of them, and
// an attempt that never completed carries no instant.
func (r *MatchingReader) freshness(ctx context.Context, intelligence *finding.Intelligence) error {
	rows, err := r.connection.Query(ctx, "SELECT source, argMax(synced_at, checked_at) FROM "+feedSyncTable+
		" WHERE feed = ? GROUP BY source ORDER BY source", intelligence.Feed.Name)
	if err != nil {
		return fmt.Errorf("read how fresh %s is: %w", intelligence.Feed.Name, err)
	}
	for rows.Next() {
		var source string
		var synced time.Time
		if err := rows.Scan(&source, &synced); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read how fresh %s is: %w", intelligence.Feed.Name, err)
		}
		synced = synced.UTC()
		if synced.Equal(time.Unix(0, 0)) {
			synced = time.Time{}
		}
		if intelligence.Feed.Source == "" || synced.Before(intelligence.Feed.SyncedAt) {
			intelligence.Feed.Source, intelligence.Feed.SyncedAt = source, synced
		}
	}
	if err := closed(rows); err != nil {
		return fmt.Errorf("read how fresh %s is: %w", intelligence.Feed.Name, err)
	}
	var fetched time.Time
	if err := r.connection.QueryRow(ctx, "SELECT max(fetched_at) FROM "+advisoryTable+" WHERE feed = ?", intelligence.Feed.Name).Scan(&fetched); err != nil {
		return fmt.Errorf("read when %s was last fetched: %w", intelligence.Feed.Name, err)
	}
	intelligence.AsOf = fetched.UTC()
	return nil
}

func (r *MatchingReader) Before(ctx context.Context, source, id string, modified time.Time, normalization uint32) ([]matching.Key, error) {
	rows, err := r.connection.Query(ctx, "SELECT DISTINCT ecosystem, package FROM "+affectedTable+
		" WHERE source = ? AND advisory_id = ? AND (modified, normalization) = (SELECT max((modified, normalization)) FROM "+advisoryTable+
		" WHERE source = ? AND advisory_id = ? AND (modified, normalization) < ("+versionPlaceholder+", ?)) ORDER BY ecosystem, package",
		source, id, source, id, modified.UnixNano(), normalization)
	if err != nil {
		return nil, fmt.Errorf("read what advisory %s named before: %w", id, err)
	}
	var keys []matching.Key
	for rows.Next() {
		var key matching.Key
		if err := rows.Scan(&key.Ecosystem, &key.Package); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read what advisory %s named before: %w", id, err)
		}
		keys = append(keys, key)
	}
	return keys, closed(rows)
}

func (r *MatchingReader) Decisions(ctx context.Context, asset matching.Asset) (map[finding.Name]*vulnerabilityv1.Finding, error) {
	rows, err := r.connection.Query(ctx, "SELECT record FROM "+findingTable+" FINAL WHERE tenant_id = ? AND agent_id = ?"+
		" ORDER BY inventory_as_of DESC, intelligence_as_of DESC, decided_at DESC LIMIT 1 BY item_id, vulnerability_id",
		asset.TenantID, asset.AgentID)
	if err != nil {
		return nil, fmt.Errorf("read the findings of agent %s: %w", asset.AgentID, err)
	}
	decided := map[finding.Name]*vulnerabilityv1.Finding{}
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read a finding of agent %s: %w", asset.AgentID, err)
		}
		var record vulnerabilityv1.FindingRecord
		if err := proto.Unmarshal([]byte(body), &record); err != nil || record.GetFinding() == nil {
			_ = rows.Close()
			return nil, fmt.Errorf("a finding of agent %s is stored as something that is not one", asset.AgentID)
		}
		made := record.GetFinding()
		decided[finding.Name{ItemID: made.GetItemId(), VulnerabilityID: made.GetVulnerabilityId()}] = made
	}
	return decided, closed(rows)
}

func (r *MatchingReader) Ping(ctx context.Context) error {
	if err := r.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the store the matcher reads: %w", err)
	}
	return nil
}

func (r *MatchingReader) Close() error { return r.connection.Close() }

const versionPlaceholder = "fromUnixTimestamp64Nano(?, 'UTC')"

var (
	packageKind = inventory.KindName(inventoryv1.Kind_KIND_PACKAGE)
	systemKind  = inventory.KindName(inventoryv1.Kind_KIND_OPERATING_SYSTEM)
)

func affectedOf(ecosystem, name string, rangeTypes []string, eventRanges []uint32, kinds, versions, listed []string, severities []*vulnerabilityv1.Severity) (*vulnerabilityv1.Affected, error) {
	entry := &vulnerabilityv1.Affected{Ecosystem: ecosystem, Name: name, Versions: listed, Severities: severities}
	for _, spelled := range rangeTypes {
		kind, known := vulnerabilityv1.Range_Type_value["TYPE_"+strings.ToUpper(spelled)]
		if !known {
			return nil, fmt.Errorf("a range of type %q", spelled)
		}
		entry.Ranges = append(entry.Ranges, &vulnerabilityv1.Range{Type: vulnerabilityv1.Range_Type(kind)})
	}
	if len(eventRanges) != len(kinds) || len(kinds) != len(versions) {
		return nil, fmt.Errorf("events of %d ranges, %d kinds and %d versions", len(eventRanges), len(kinds), len(versions))
	}
	for index, position := range eventRanges {
		if int(position) >= len(entry.Ranges) {
			return nil, fmt.Errorf("an event of range %d among %d", position, len(entry.Ranges))
		}
		event := &vulnerabilityv1.Event{}
		switch kinds[index] {
		case "introduced":
			event.Boundary = &vulnerabilityv1.Event_Introduced{Introduced: versions[index]}
		case "fixed":
			event.Boundary = &vulnerabilityv1.Event_Fixed{Fixed: versions[index]}
		case "last_affected":
			event.Boundary = &vulnerabilityv1.Event_LastAffected{LastAffected: versions[index]}
		case "limit":
			event.Boundary = &vulnerabilityv1.Event_Limit{Limit: versions[index]}
		default:
			return nil, fmt.Errorf("an event of kind %q", kinds[index])
		}
		entry.Ranges[position].Events = append(entry.Ranges[position].Events, event)
	}
	return entry, nil
}

func severitiesOf(types, scores, assessors []string) []*vulnerabilityv1.Severity {
	var severities []*vulnerabilityv1.Severity
	for index, spelled := range types {
		if index >= len(scores) || index >= len(assessors) {
			break
		}
		kind := vulnerabilityv1.Severity_Type_value["TYPE_"+strings.ToUpper(spelled)]
		severities = append(severities, &vulnerabilityv1.Severity{Type: vulnerabilityv1.Severity_Type(kind), Score: scores[index], AssessedBy: assessors[index]})
	}
	return severities
}

func strings2any(values []string) []any {
	arguments := make([]any, 0, len(values))
	for _, value := range slices.SortedFunc(slices.Values(values), cmp.Compare[string]) {
		arguments = append(arguments, value)
	}
	return arguments
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func closed(rows driver.Rows) error {
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	return rows.Close()
}
