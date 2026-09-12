package clickhouse

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/dynasmon/Seagull-backend-v2/internal/inventorystore"
)

const (
	inventoryTable = "asset_inventory"
	scanTable      = "asset_inventory_scans"
)

// The writer and the final migrated schema must name columns in the same order.
var inventoryColumns = []string{
	"tenant_id",
	"agent_id",
	"kind",
	"item_id",

	"last_seen",
	"mode",
	"record_id",
	"schema_version",

	"host_hostname",
	"host_ip",
	"host_os",
	"host_architecture",

	"collector",
	"source",
	"sequence",

	"gateway",
	"batch_id",
	"ingest_time",

	"os_name",
	"os_version",
	"os_build",
	"os_platform",
	"os_codename",
	"os_family",

	"kernel_name",
	"kernel_release",
	"kernel_version",
	"kernel_architecture",

	"package_name",
	"package_version",
	"package_architecture",
	"package_manager",
	"package_source",
	"package_vendor",
	"package_size_bytes",
	"package_installed_at",

	"service_name",
	"service_display_name",
	"service_state",
	"service_start_mode",
	"service_path",

	"interface_name",
	"interface_mac",
	"interface_addresses",
	"interface_state",
	"interface_mtu",
	"interface_type",

	"user_name",
	"user_uid",
	"user_gid",
	"user_home",
	"user_shell",
	"user_groups",
	"user_last_login",

	"hardware_cpu_name",
	"hardware_cpu_cores",
	"hardware_cpu_mhz",
	"hardware_memory_total_bytes",
	"hardware_serial",
	"hardware_vendor",
	"hardware_model",

	"process_pid",
	"process_parent_pid",
	"process_name",
	"process_path",
	"process_command_line",
	"process_user",
	"process_started_at",
}

var scanColumns = []string{
	"tenant_id",
	"agent_id",
	"kind",
	"scanned_at",
	"record_id",
	"items",
}

// An array column is never handed a nil: the driver writes what it is given and
// a column the schema declares NOT NULL is not the place to find out.
func inventoryValues(row inventorystore.Row) []any {
	return []any{
		row.TenantID,
		row.AgentID,
		row.Kind,
		row.ItemID,

		row.LastSeen,
		row.Mode,
		row.RecordID,
		row.SchemaVersion,

		row.HostHostname,
		row.HostIP,
		row.HostOS,
		row.HostArchitecture,

		row.Collector,
		row.Source,
		row.Sequence,

		row.Gateway,
		row.BatchID,
		row.IngestTime,

		row.OSName,
		row.OSVersion,
		row.OSBuild,
		row.OSPlatform,
		row.OSCodename,
		row.OSFamily,

		row.KernelName,
		row.KernelRelease,
		row.KernelVersion,
		row.KernelArchitecture,

		row.PackageName,
		row.PackageVersion,
		row.PackageArchitecture,
		row.PackageManager,
		row.PackageSource,
		row.PackageVendor,
		row.PackageSizeBytes,
		row.PackageInstalledAt,

		row.ServiceName,
		row.ServiceDisplayName,
		row.ServiceState,
		row.ServiceStartMode,
		row.ServicePath,

		row.InterfaceName,
		row.InterfaceMAC,
		listed(row.InterfaceAddresses),
		row.InterfaceState,
		row.InterfaceMTU,
		row.InterfaceType,

		row.UserName,
		row.UserUID,
		row.UserGID,
		row.UserHome,
		row.UserShell,
		listed(row.UserGroups),
		row.UserLastLogin,

		row.HardwareCPUName,
		row.HardwareCPUCores,
		row.HardwareCPUMHz,
		row.HardwareMemoryTotalBytes,
		row.HardwareSerial,
		row.HardwareVendor,
		row.HardwareModel,

		row.ProcessPID,
		row.ProcessParentPID,
		row.ProcessName,
		row.ProcessPath,
		row.ProcessCommandLine,
		row.ProcessUser,
		row.ProcessStartedAt,
	}
}

func scanValues(scan inventorystore.Scan) []any {
	return []any{
		scan.TenantID,
		scan.AgentID,
		scan.Kind,
		scan.ScannedAt,
		scan.RecordID,
		scan.Items,
	}
}

func listed(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

type InventoryStore struct {
	connection driver.Conn
	database   string
	insertRows string
	insertScan string
}

func NewInventoryStore(configuration Config) (*InventoryStore, error) {
	if err := inventoryAgreesWithSchema(); err != nil {
		return nil, err
	}

	connection, err := connect(configuration)
	if err != nil {
		return nil, err
	}

	return &InventoryStore{
		connection: connection,
		database:   configuration.Database,
		insertRows: fmt.Sprintf("INSERT INTO %s (%s)", inventoryTable, strings.Join(inventoryColumns, ", ")),
		insertScan: fmt.Sprintf("INSERT INTO %s (%s)", scanTable, strings.Join(scanColumns, ", ")),
	}, nil
}

// The items land before the line absence is measured against moves, never the
// other way: a reader that saw the new line and none of its items would read a
// whole asset as having nothing installed.
func (s *InventoryStore) Store(ctx context.Context, rows []inventorystore.Row, scans []inventorystore.Scan) error {
	if err := s.write(ctx, s.insertRows, inventoryTable, len(rows), func(batch driver.Batch) error {
		for _, row := range rows {
			if err := batch.Append(inventoryValues(row)...); err != nil {
				return fmt.Errorf("add item %s to the batch: %w", row.ItemID, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return s.write(ctx, s.insertScan, scanTable, len(scans), func(batch driver.Batch) error {
		for _, scan := range scans {
			if err := batch.Append(scanValues(scan)...); err != nil {
				return fmt.Errorf("add the %s scan of agent %s to the batch: %w", scan.Kind, scan.AgentID, err)
			}
		}
		return nil
	})
}

func (s *InventoryStore) write(ctx context.Context, statement, table string, count int, fill func(driver.Batch) error) error {
	if count == 0 {
		return nil
	}

	batch, err := s.connection.PrepareBatch(ctx, statement)
	if err != nil {
		return fmt.Errorf("open a batch on %s: %w", table, err)
	}
	if err := fill(batch); err != nil {
		_ = batch.Abort()
		return err
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("write %d rows to %s: %w", count, table, err)
	}
	return nil
}

func (s *InventoryStore) Ping(ctx context.Context) error {
	if err := s.connection.Ping(ctx); err != nil {
		return fmt.Errorf("reach the inventory store: %w", err)
	}
	return nil
}

func (s *InventoryStore) VerifySchema(ctx context.Context) error {
	outstanding, err := pending(ctx, s.connection)
	if err != nil {
		return err
	}
	if len(outstanding) > 0 {
		names := make([]string, 0, len(outstanding))
		for _, entry := range outstanding {
			names = append(names, entry.String())
		}
		return fmt.Errorf("the inventory store is missing %d migration(s): %s — run store-migrator",
			len(outstanding), strings.Join(names, ", "))
	}
	if err := columnsPresent(ctx, s.connection, s.database, inventoryTable, inventoryColumns); err != nil {
		return err
	}
	return columnsPresent(ctx, s.connection, s.database, scanTable, scanColumns)
}

func (s *InventoryStore) Close() error { return s.connection.Close() }

func inventoryAgreesWithSchema() error {
	for _, agreement := range []struct {
		table   string
		columns []string
		values  int
	}{
		{inventoryTable, inventoryColumns, len(inventoryValues(inventorystore.Row{}))},
		{scanTable, scanColumns, len(scanValues(inventorystore.Scan{}))},
	} {
		declared, err := declaredColumns(agreement.table)
		if err != nil {
			return err
		}
		if !slices.Equal(declared, agreement.columns) {
			return fmt.Errorf("the store writes %d columns of %s and the migrated schema defines %d: %s versus %s",
				len(agreement.columns), agreement.table, len(declared),
				strings.Join(agreement.columns, ", "), strings.Join(declared, ", "))
		}
		if agreement.values != len(agreement.columns) {
			return fmt.Errorf("the store names %d columns of %s and supplies %d values",
				len(agreement.columns), agreement.table, agreement.values)
		}
	}
	return nil
}
