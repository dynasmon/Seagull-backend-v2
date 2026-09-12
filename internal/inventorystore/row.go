package inventorystore

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// The contract reaches the year 9999 and the store does not, and an instant no
// item of this kind carries is absent rather than the year one, which the column
// cannot hold either. Outside these bounds UnixNano wraps silently.
var (
	epoch    = time.Unix(0, 0).UTC()
	earliest = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)
	latest   = time.Date(2262, time.April, 11, 23, 47, 16, 0, time.UTC)
)

type Row struct {
	TenantID string
	AgentID  string
	Kind     string
	ItemID   string

	LastSeen      time.Time
	Mode          string
	RecordID      string
	SchemaVersion uint32

	HostHostname     string
	HostIP           string
	HostOS           string
	HostArchitecture string

	Collector string
	Source    string
	Sequence  uint64

	Gateway    string
	BatchID    string
	IngestTime time.Time

	OSName     string
	OSVersion  string
	OSBuild    string
	OSPlatform string
	OSCodename string
	OSFamily   string

	KernelName         string
	KernelRelease      string
	KernelVersion      string
	KernelArchitecture string

	PackageName         string
	PackageVersion      string
	PackageArchitecture string
	PackageManager      string
	PackageSource       string
	PackageVendor       string
	PackageSizeBytes    uint64
	PackageInstalledAt  time.Time

	ServiceName        string
	ServiceDisplayName string
	ServiceState       string
	ServiceStartMode   string
	ServicePath        string

	InterfaceName      string
	InterfaceMAC       string
	InterfaceAddresses []string
	InterfaceState     string
	InterfaceMTU       uint32
	InterfaceType      string

	UserName      string
	UserUID       string
	UserGID       string
	UserHome      string
	UserShell     string
	UserGroups    []string
	UserLastLogin time.Time

	HardwareCPUName          string
	HardwareCPUCores         uint32
	HardwareCPUMHz           uint32
	HardwareMemoryTotalBytes uint64
	HardwareSerial           string
	HardwareVendor           string
	HardwareModel            string

	ProcessPID         uint32
	ProcessParentPID   uint32
	ProcessName        string
	ProcessPath        string
	ProcessCommandLine string
	ProcessUser        string
	ProcessStartedAt   time.Time
}

// When one asset's inventory of one kind was last enumerated in full. Absence
// only means something against this line, and only a full enumeration moves it:
// a delta names what it names and says nothing at all about what it leaves out,
// so a delta that moved this would retire every item it did not mention.
type Scan struct {
	TenantID  string
	AgentID   string
	Kind      string
	ScannedAt time.Time
	RecordID  string
	Items     uint32
}

// Every contract leaf this projection keeps. A field added to the contract fails
// the coverage test until it is listed here.
var carried = []string{
	"collected_at",
	"collection.collector",
	"collection.sequence",
	"collection.source",
	"items.hardware.cpu_cores",
	"items.hardware.cpu_mhz",
	"items.hardware.cpu_name",
	"items.hardware.memory_total_bytes",
	"items.hardware.model",
	"items.hardware.serial",
	"items.hardware.vendor",
	"items.kernel.architecture",
	"items.kernel.name",
	"items.kernel.release",
	"items.kernel.version",
	"items.network_interface.addresses",
	"items.network_interface.mac",
	"items.network_interface.mtu",
	"items.network_interface.name",
	"items.network_interface.state",
	"items.network_interface.type",
	"items.operating_system.build",
	"items.operating_system.codename",
	"items.operating_system.family",
	"items.operating_system.name",
	"items.operating_system.platform",
	"items.operating_system.version",
	"items.package.architecture",
	"items.package.installed_at",
	"items.package.manager",
	"items.package.name",
	"items.package.size_bytes",
	"items.package.source",
	"items.package.vendor",
	"items.package.version",
	"items.process.command_line",
	"items.process.name",
	"items.process.parent_pid",
	"items.process.path",
	"items.process.pid",
	"items.process.started_at",
	"items.process.user",
	"items.service.display_name",
	"items.service.name",
	"items.service.path",
	"items.service.start_mode",
	"items.service.state",
	"items.user.gid",
	"items.user.groups",
	"items.user.home",
	"items.user.last_login",
	"items.user.name",
	"items.user.shell",
	"items.user.uid",
	"kind",
	"mode",
	"origin.agent_id",
	"origin.host.architecture",
	"origin.host.hostname",
	"origin.host.ip",
	"origin.host.os",
	"origin.tenant_id",
	"reception.batch_id",
	"reception.gateway",
	"reception.ingest_time",
	"record_id",
	"schema_version",
}

func Project(record *inventoryv1.Record) []Row {
	kind := record.GetKind()
	common := Row{
		TenantID: record.GetOrigin().GetTenantId(),
		AgentID:  record.GetOrigin().GetAgentId(),
		Kind:     inventory.KindName(kind),

		LastSeen:      instant(record.GetCollectedAt()),
		Mode:          inventory.ModeName(record.GetMode()),
		RecordID:      record.GetRecordId(),
		SchemaVersion: record.GetSchemaVersion(),

		HostHostname:     record.GetOrigin().GetHost().GetHostname(),
		HostIP:           record.GetOrigin().GetHost().GetIp(),
		HostOS:           record.GetOrigin().GetHost().GetOs(),
		HostArchitecture: record.GetOrigin().GetHost().GetArchitecture(),

		Collector: record.GetCollection().GetCollector(),
		Source:    record.GetCollection().GetSource(),
		Sequence:  record.GetCollection().GetSequence(),

		Gateway:    record.GetReception().GetGateway(),
		BatchID:    record.GetReception().GetBatchId(),
		IngestTime: instant(record.GetReception().GetIngestTime()),

		PackageInstalledAt: epoch,
		UserLastLogin:      epoch,
		ProcessStartedAt:   epoch,
	}

	rows := make([]Row, 0, len(record.GetItems()))
	for _, item := range record.GetItems() {
		row := common
		row.ItemID = inventory.ItemID(kind, item)
		fill(&row, item)
		rows = append(rows, row)
	}
	return rows
}

func Scanned(record *inventoryv1.Record) (Scan, bool) {
	if record.GetMode() != inventoryv1.Mode_MODE_SNAPSHOT {
		return Scan{}, false
	}
	return Scan{
		TenantID:  record.GetOrigin().GetTenantId(),
		AgentID:   record.GetOrigin().GetAgentId(),
		Kind:      inventory.KindName(record.GetKind()),
		ScannedAt: instant(record.GetCollectedAt()),
		RecordID:  record.GetRecordId(),
		Items:     uint32(len(record.GetItems())),
	}, true
}

func fill(row *Row, item *inventoryv1.Item) {
	switch body := item.GetBody().(type) {
	case *inventoryv1.Item_OperatingSystem:
		operating := body.OperatingSystem
		row.OSName = operating.GetName()
		row.OSVersion = operating.GetVersion()
		row.OSBuild = operating.GetBuild()
		row.OSPlatform = operating.GetPlatform()
		row.OSCodename = operating.GetCodename()
		row.OSFamily = operating.GetFamily()
	case *inventoryv1.Item_Kernel:
		kernel := body.Kernel
		row.KernelName = kernel.GetName()
		row.KernelRelease = kernel.GetRelease()
		row.KernelVersion = kernel.GetVersion()
		row.KernelArchitecture = kernel.GetArchitecture()
	case *inventoryv1.Item_Package:
		installed := body.Package
		row.PackageName = installed.GetName()
		row.PackageVersion = installed.GetVersion()
		row.PackageArchitecture = installed.GetArchitecture()
		row.PackageManager = installed.GetManager()
		row.PackageSource = installed.GetSource()
		row.PackageVendor = installed.GetVendor()
		row.PackageSizeBytes = installed.GetSizeBytes()
		row.PackageInstalledAt = instant(installed.GetInstalledAt())
	case *inventoryv1.Item_Service:
		service := body.Service
		row.ServiceName = service.GetName()
		row.ServiceDisplayName = service.GetDisplayName()
		row.ServiceState = name(service.GetState().String(), "STATE_")
		row.ServiceStartMode = service.GetStartMode()
		row.ServicePath = service.GetPath()
	case *inventoryv1.Item_NetworkInterface:
		adapter := body.NetworkInterface
		row.InterfaceName = adapter.GetName()
		row.InterfaceMAC = adapter.GetMac()
		row.InterfaceAddresses = adapter.GetAddresses()
		row.InterfaceState = name(adapter.GetState().String(), "STATE_")
		row.InterfaceMTU = adapter.GetMtu()
		row.InterfaceType = adapter.GetType()
	case *inventoryv1.Item_User:
		account := body.User
		row.UserName = account.GetName()
		row.UserUID = account.GetUid()
		row.UserGID = account.GetGid()
		row.UserHome = account.GetHome()
		row.UserShell = account.GetShell()
		row.UserGroups = account.GetGroups()
		row.UserLastLogin = instant(account.GetLastLogin())
	case *inventoryv1.Item_Hardware:
		hardware := body.Hardware
		row.HardwareCPUName = hardware.GetCpuName()
		row.HardwareCPUCores = hardware.GetCpuCores()
		row.HardwareCPUMHz = hardware.GetCpuMhz()
		row.HardwareMemoryTotalBytes = hardware.GetMemoryTotalBytes()
		row.HardwareSerial = hardware.GetSerial()
		row.HardwareVendor = hardware.GetVendor()
		row.HardwareModel = hardware.GetModel()
	case *inventoryv1.Item_Process:
		running := body.Process
		row.ProcessPID = running.GetPid()
		row.ProcessParentPID = running.GetParentPid()
		row.ProcessName = running.GetName()
		row.ProcessPath = running.GetPath()
		row.ProcessCommandLine = running.GetCommandLine()
		row.ProcessUser = running.GetUser()
		row.ProcessStartedAt = instant(running.GetStartedAt())
	}
}

func name(value, prefix string) string {
	trimmed := strings.TrimPrefix(value, prefix)
	if trimmed == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(trimmed)
}

func instant(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return epoch
	}
	return value.AsTime().UTC()
}

// Checked before the batch is built, so one unrepresentable record is refused to
// quarantine rather than failing the batch it shares.
func storable(row Row) error {
	for _, held := range []struct {
		field string
		at    time.Time
	}{
		{"collected_at", row.LastSeen},
		{"reception.ingest_time", row.IngestTime},
		{"items.package.installed_at", row.PackageInstalledAt},
		{"items.user.last_login", row.UserLastLogin},
		{"items.process.started_at", row.ProcessStartedAt},
	} {
		if held.at.Before(earliest) || held.at.After(latest) {
			return fmt.Errorf("%s is outside the %s..%s the store can hold",
				held.field, earliest.Format(time.DateOnly), latest.Format(time.DateOnly))
		}
	}
	return nil
}
