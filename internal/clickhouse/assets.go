package clickhouse

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventorystore"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// What tells one instance of a kind from another, in the order a listing sorts
// and resumes by: the parts ADR 43 names an instance by, so two rows saying the
// same thing sort together and are listed once, and an identity alone where a
// kind holds one of a name.
type keyPart struct {
	column string
	bind   string
	of     func(inventorystore.Row) string
	parse  func(string) (any, error)
}

func textKey(column string, of func(inventorystore.Row) string) keyPart {
	return keyPart{column: column, bind: "?", of: of, parse: func(value string) (any, error) { return value, nil }}
}

func numberKey(column string, of func(inventorystore.Row) uint32) keyPart {
	return keyPart{column: column, bind: "?",
		of: func(row inventorystore.Row) string { return strconv.FormatUint(uint64(of(row)), 10) },
		parse: func(value string) (any, error) {
			parsed, err := strconv.ParseUint(value, 10, 32)
			return uint32(parsed), err
		}}
}

func instantKey(column string, of func(inventorystore.Row) time.Time) keyPart {
	return keyPart{column: column, bind: instantPlaceholder,
		of:    func(row inventorystore.Row) string { return strconv.FormatInt(of(row).UnixMilli(), 10) },
		parse: func(value string) (any, error) { return strconv.ParseInt(value, 10, 64) }}
}

var (
	identifiedAlone = textKey("item_id", func(row inventorystore.Row) string { return row.ItemID })
	lastSeenKey     = instantKey("last_seen", func(row inventorystore.Row) time.Time { return row.LastSeen })
)

var instanceKeys = map[inventoryv1.Kind][]keyPart{
	inventoryv1.Kind_KIND_OPERATING_SYSTEM: {identifiedAlone},
	inventoryv1.Kind_KIND_KERNEL:           {identifiedAlone},
	inventoryv1.Kind_KIND_HARDWARE:         {identifiedAlone},
	inventoryv1.Kind_KIND_PACKAGE: {
		textKey("package_name", func(row inventorystore.Row) string { return row.PackageName }),
		textKey("package_version", func(row inventorystore.Row) string { return row.PackageVersion }),
		textKey("package_architecture", func(row inventorystore.Row) string { return row.PackageArchitecture }),
		textKey("package_manager", func(row inventorystore.Row) string { return row.PackageManager }),
	},
	inventoryv1.Kind_KIND_SERVICE: {textKey("service_name", func(row inventorystore.Row) string { return row.ServiceName })},
	inventoryv1.Kind_KIND_NETWORK_INTERFACE: {
		textKey("interface_name", func(row inventorystore.Row) string { return row.InterfaceName }),
	},
	inventoryv1.Kind_KIND_USER: {
		textKey("user_uid", func(row inventorystore.Row) string { return row.UserUID }),
		textKey("user_name", func(row inventorystore.Row) string { return row.UserName }),
	},
	inventoryv1.Kind_KIND_PROCESS: {
		numberKey("process_pid", func(row inventorystore.Row) uint32 { return row.ProcessPID }),
		instantKey("process_started_at", func(row inventorystore.Row) time.Time { return row.ProcessStartedAt }),
	},
}

var nameColumns = map[inventoryv1.Kind]string{
	inventoryv1.Kind_KIND_OPERATING_SYSTEM:  "os_name",
	inventoryv1.Kind_KIND_KERNEL:            "kernel_name",
	inventoryv1.Kind_KIND_PACKAGE:           "package_name",
	inventoryv1.Kind_KIND_SERVICE:           "service_name",
	inventoryv1.Kind_KIND_NETWORK_INTERFACE: "interface_name",
	inventoryv1.Kind_KIND_USER:              "user_name",
	inventoryv1.Kind_KIND_PROCESS:           "process_name",
}

// An asset is listed by its enumerations, which the store keeps a row per kind
// of, and only the page's assets are read in the item table for their host and
// for when anything on them was last seen.
func (h *Hunter) Assets(ctx context.Context, asked hunt.AssetQuestion) (*inventoryv1.AssetPage, []string, error) {
	tenants := asked.Scope().Tenants()
	ctx = budgeted(ctx, asked.Timeout(), asked.MaxRowsRead())

	conditions := []string{"tenant_id IN (" + placeholders(len(tenants)) + ")"}
	arguments := valuesOf(tenants)
	if agents := asked.Agents(); len(agents) > 0 {
		conditions = append(conditions, "agent_id IN ("+placeholders(len(agents))+")")
		arguments = append(arguments, valuesOf(agents)...)
	}
	if after := asked.After(); len(after) > 0 {
		if len(after) != 2 {
			return nil, nil, fmt.Errorf("a position among assets names %d values and an asset is named by 2", len(after))
		}
		conditions = append(conditions, "(tenant_id, agent_id) > (?, ?)")
		arguments = append(arguments, after[0], after[1])
	}
	having := ""
	if before, set := asked.ScannedBefore(); set {
		having = " HAVING min(scanned_at) < " + instantPlaceholder
		arguments = append(arguments, before.UnixMilli())
	}

	rows, err := h.connection.Query(ctx, "SELECT tenant_id, agent_id, groupArray(kind), groupArray(scanned_at), groupArray(record_id), groupArray(items)"+
		" FROM "+scanTable+" FINAL WHERE "+strings.Join(conditions, " AND ")+" GROUP BY tenant_id, agent_id"+having+
		" ORDER BY tenant_id, agent_id LIMIT "+strconv.Itoa(asked.Limit()), arguments...)
	if err != nil {
		return nil, nil, fmt.Errorf("list the assets: %w", err)
	}
	page := &inventoryv1.AssetPage{}
	byName := map[[2]string]*inventoryv1.Asset{}
	for rows.Next() {
		var (
			asset    inventoryv1.Asset
			kinds    []string
			scanned  []time.Time
			records  []string
			counted  []uint32
			newestAt time.Time
		)
		if err := rows.Scan(&asset.TenantId, &asset.AgentId, &kinds, &scanned, &records, &counted); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("read an asset: %w", err)
		}
		for index, name := range kinds {
			kind, known := inventory.KindOf(name)
			if !known || index >= len(scanned) || index >= len(records) || index >= len(counted) {
				continue
			}
			asset.Scans = append(asset.Scans, &inventoryv1.Scan{Kind: kind, ScannedAt: timestamppb.New(scanned[index].UTC()), RecordId: records[index], Items: counted[index]})
			newestAt = latest(newestAt, scanned[index].UTC())
		}
		slices.SortFunc(asset.Scans, func(a, b *inventoryv1.Scan) int { return int(a.GetKind()) - int(b.GetKind()) })
		asset.LastSeen = timestamppb.New(newestAt)
		page.Assets = append(page.Assets, &asset)
		byName[[2]string{asset.TenantId, asset.AgentId}] = &asset
	}
	if err := closed(rows); err != nil {
		return nil, nil, fmt.Errorf("list the assets: %w", err)
	}
	if len(page.Assets) == 0 {
		return page, nil, nil
	}
	if err := h.described(ctx, page.Assets, byName); err != nil {
		return nil, nil, err
	}
	last := page.Assets[len(page.Assets)-1]
	return page, []string{last.GetTenantId(), last.GetAgentId()}, nil
}

func (h *Hunter) described(ctx context.Context, assets []*inventoryv1.Asset, byName map[[2]string]*inventoryv1.Asset) error {
	var tenants, agents []string
	for _, asset := range assets {
		if !slices.Contains(tenants, asset.GetTenantId()) {
			tenants = append(tenants, asset.GetTenantId())
		}
		agents = append(agents, asset.GetAgentId())
	}
	rows, err := h.connection.Query(ctx, "SELECT tenant_id, agent_id, max(last_seen), argMax(host_hostname, last_seen), argMax(host_ip, last_seen),"+
		" argMax(host_os, last_seen), argMax(host_architecture, last_seen) FROM "+inventoryTable+
		" WHERE tenant_id IN ("+placeholders(len(tenants))+") AND agent_id IN ("+placeholders(len(agents))+") GROUP BY tenant_id, agent_id",
		append(valuesOf(tenants), valuesOf(agents)...)...)
	if err != nil {
		return fmt.Errorf("read the hosts of %d assets: %w", len(assets), err)
	}
	for rows.Next() {
		var (
			row  inventorystore.Row
			seen time.Time
		)
		if err := rows.Scan(&row.TenantID, &row.AgentID, &seen, &row.HostHostname, &row.HostIP, &row.HostOS, &row.HostArchitecture); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read the host of an asset: %w", err)
		}
		asset := byName[[2]string{row.TenantID, row.AgentID}]
		if asset == nil {
			continue
		}
		asset.Host = inventorystore.HostOf(row)
		asset.LastSeen = timestamppb.New(latest(asset.GetLastSeen().AsTime().UTC(), seen.UTC()))
	}
	if err := closed(rows); err != nil {
		return fmt.Errorf("read the hosts of %d assets: %w", len(assets), err)
	}
	return nil
}

// An item listing reads one kind of one asset. Without a name it is what the
// asset holds now, by currentAgainst; with one it is every instance of that
// name the asset was seen with, newest first, each saying whether it still is.
func (h *Hunter) Items(ctx context.Context, asked hunt.ItemQuestion) (*inventoryv1.ItemPage, []string, error) {
	keys := instanceKeys[asked.Kind()]
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("an item of %s has no key to be listed by", asked.Kind())
	}
	kind := inventory.KindName(asked.Kind())
	tenants := asked.Scope().Tenants()
	ctx = budgeted(ctx, asked.Timeout(), asked.MaxRowsRead())

	enumerated, err := enumerations(ctx, h.connection, tenants, asked.Agent(), []string{kind})
	if err != nil {
		return nil, nil, err
	}
	page := &inventoryv1.ItemPage{}
	if line, scanned := enumerated[kind]; scanned {
		page.Scan = &inventoryv1.Scan{Kind: asked.Kind(), ScannedAt: timestamppb.New(line.scannedAt), RecordId: line.recordID, Items: line.items}
	}
	held, heldArguments := currentAgainst([]string{kind}, enumerated)

	key := make([]string, len(keys))
	descending := make([]string, len(keys))
	for index, part := range keys {
		key[index], descending[index] = part.column, part.column+" DESC"
	}
	conditions := []string{"tenant_id IN (" + placeholders(len(tenants)) + ")", "agent_id = ?", "kind = ?"}
	arguments := append(valuesOf(tenants), asked.Agent(), kind)
	newest := " ORDER BY " + strings.Join(key, ", ") + ", last_seen DESC, item_id DESC LIMIT 1 BY " + strings.Join(key, ", ")
	columns := strings.Join(inventoryColumns, ", ")

	var statement string
	resumed := keys
	name, history := asked.Name()
	if !history {
		conditions, arguments = append(conditions, held), append(arguments, heldArguments...)
		if after := asked.After(); len(after) > 0 {
			bound, values, err := positioned(keys, after, ">")
			if err != nil {
				return nil, nil, err
			}
			conditions, arguments = append(conditions, bound), append(arguments, values...)
		}
		statement = "SELECT " + columns + ", 1 FROM " + inventoryTable + " FINAL WHERE " + strings.Join(conditions, " AND ") +
			newest + " LIMIT " + strconv.Itoa(asked.Limit())
	} else {
		column := nameColumns[asked.Kind()]
		if column == "" {
			return nil, nil, fmt.Errorf("an item of %s carries no name to be asked by", asked.Kind())
		}
		conditions, arguments = append(conditions, column+" = ?"), append(arguments, name)
		resumed = append([]keyPart{lastSeenKey}, keys...)
		outer := ""
		var after []any
		if position := asked.After(); len(position) > 0 {
			bound, values, err := positioned(resumed, position, "<")
			if err != nil {
				return nil, nil, err
			}
			outer, after = " WHERE "+bound, values
		}
		statement = "SELECT " + columns + ", " + held + " FROM (SELECT " + columns + " FROM " + inventoryTable + " FINAL WHERE " +
			strings.Join(conditions, " AND ") + newest + ")" + outer +
			" ORDER BY last_seen DESC, " + strings.Join(descending, ", ") + " LIMIT " + strconv.Itoa(asked.Limit())
		arguments = append(append(heldArguments, arguments...), after...)
	}

	rows, err := h.connection.Query(ctx, statement, arguments...)
	if err != nil {
		return nil, nil, fmt.Errorf("list the %s of agent %s: %w", kind, asked.Agent(), err)
	}
	var last inventorystore.Row
	for rows.Next() {
		var (
			row     inventorystore.Row
			current uint8
		)
		if err := rows.Scan(append(inventoryPointers(&row), &current)...); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("read an item of agent %s: %w", asked.Agent(), err)
		}
		row.LastSeen = row.LastSeen.UTC()
		page.Items = append(page.Items, &inventoryv1.HeldItem{
			ItemId: row.ItemID, Kind: asked.Kind(), Item: inventorystore.Restore(row),
			LastSeen: timestamppb.New(row.LastSeen), RecordId: row.RecordID, Current: current != 0,
		})
		last = row
	}
	if err := closed(rows); err != nil {
		return nil, nil, fmt.Errorf("list the %s of agent %s: %w", kind, asked.Agent(), err)
	}
	if len(page.Items) == 0 {
		return page, nil, nil
	}
	position := make([]string, len(resumed))
	for index, part := range resumed {
		position[index] = part.of(last)
	}
	return page, position, nil
}

func positioned(parts []keyPart, values []string, comparison string) (string, []any, error) {
	if len(values) != len(parts) {
		return "", nil, fmt.Errorf("a position names %d values and this listing sorts by %d", len(values), len(parts))
	}
	columns, binds := make([]string, len(parts)), make([]string, len(parts))
	arguments := make([]any, len(parts))
	for index, part := range parts {
		parsed, err := part.parse(values[index])
		if err != nil {
			return "", nil, fmt.Errorf("a position holds %q for %s: %w", values[index], part.column, err)
		}
		columns[index], binds[index], arguments[index] = part.column, part.bind, parsed
	}
	return "(" + strings.Join(columns, ", ") + ") " + comparison + " (" + strings.Join(binds, ", ") + ")", arguments, nil
}

// The budget travels with each statement rather than with the connection, so
// one caller cannot spend another's allowance and the store stops the read
// itself instead of being abandoned mid-scan.
func budgeted(ctx context.Context, timeout time.Duration, rows uint64) context.Context {
	return clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{
		"max_execution_time":    int(math.Ceil(timeout.Seconds())),
		"timeout_overflow_mode": "throw",
		"max_rows_to_read":      rows,
		"read_overflow_mode":    "throw",
	}))
}

func valuesOf(values []string) []any {
	arguments := make([]any, len(values))
	for index, value := range values {
		arguments[index] = value
	}
	return arguments
}
