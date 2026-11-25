package inventorystore

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// The inverse of fill: what a reader is handed is the item the collector
// reported, never a row, so the store's columns stay a detail of the store. A
// row of a kind this build does not know restores as an item with no body.
func Restore(row Row) *inventoryv1.Item {
	switch row.Kind {
	case inventory.KindName(inventoryv1.Kind_KIND_OPERATING_SYSTEM):
		return &inventoryv1.Item{Body: &inventoryv1.Item_OperatingSystem{OperatingSystem: &inventoryv1.OperatingSystem{
			Name: row.OSName, Version: row.OSVersion, Build: row.OSBuild,
			Platform: row.OSPlatform, Codename: row.OSCodename, Family: row.OSFamily,
		}}}
	case inventory.KindName(inventoryv1.Kind_KIND_KERNEL):
		return &inventoryv1.Item{Body: &inventoryv1.Item_Kernel{Kernel: &inventoryv1.Kernel{
			Name: row.KernelName, Release: row.KernelRelease, Version: row.KernelVersion, Architecture: row.KernelArchitecture,
		}}}
	case inventory.KindName(inventoryv1.Kind_KIND_PACKAGE):
		return &inventoryv1.Item{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{
			Name: row.PackageName, Version: row.PackageVersion, Architecture: row.PackageArchitecture,
			Manager: row.PackageManager, Source: row.PackageSource, Vendor: row.PackageVendor,
			SizeBytes: row.PackageSizeBytes, InstalledAt: given(row.PackageInstalledAt),
		}}}
	case inventory.KindName(inventoryv1.Kind_KIND_SERVICE):
		return &inventoryv1.Item{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{
			Name: row.ServiceName, DisplayName: row.ServiceDisplayName,
			State:     inventoryv1.Service_State(inventoryv1.Service_State_value[stateName(row.ServiceState)]),
			StartMode: row.ServiceStartMode, Path: row.ServicePath,
		}}}
	case inventory.KindName(inventoryv1.Kind_KIND_NETWORK_INTERFACE):
		return &inventoryv1.Item{Body: &inventoryv1.Item_NetworkInterface{NetworkInterface: &inventoryv1.NetworkInterface{
			Name: row.InterfaceName, Mac: row.InterfaceMAC, Addresses: row.InterfaceAddresses,
			State: inventoryv1.NetworkInterface_State(inventoryv1.NetworkInterface_State_value[stateName(row.InterfaceState)]),
			Mtu:   row.InterfaceMTU, Type: row.InterfaceType,
		}}}
	case inventory.KindName(inventoryv1.Kind_KIND_USER):
		return &inventoryv1.Item{Body: &inventoryv1.Item_User{User: &inventoryv1.User{
			Name: row.UserName, Uid: row.UserUID, Gid: row.UserGID, Home: row.UserHome,
			Shell: row.UserShell, Groups: row.UserGroups, LastLogin: given(row.UserLastLogin),
		}}}
	case inventory.KindName(inventoryv1.Kind_KIND_HARDWARE):
		return &inventoryv1.Item{Body: &inventoryv1.Item_Hardware{Hardware: &inventoryv1.Hardware{
			CpuName: row.HardwareCPUName, CpuCores: row.HardwareCPUCores, CpuMhz: row.HardwareCPUMHz,
			MemoryTotalBytes: row.HardwareMemoryTotalBytes, Serial: row.HardwareSerial,
			Vendor: row.HardwareVendor, Model: row.HardwareModel,
		}}}
	case inventory.KindName(inventoryv1.Kind_KIND_PROCESS):
		return &inventoryv1.Item{Body: &inventoryv1.Item_Process{Process: &inventoryv1.Process{
			Pid: row.ProcessPID, ParentPid: row.ProcessParentPID, Name: row.ProcessName, Path: row.ProcessPath,
			CommandLine: row.ProcessCommandLine, User: row.ProcessUser, StartedAt: given(row.ProcessStartedAt),
		}}}
	}
	return &inventoryv1.Item{}
}

// The host as the record that wrote this row named it.
func HostOf(row Row) *eventv1.Host {
	if row.HostHostname == "" && row.HostIP == "" && row.HostOS == "" && row.HostArchitecture == "" {
		return nil
	}
	return &eventv1.Host{Hostname: row.HostHostname, Ip: row.HostIP, Os: row.HostOS, Architecture: row.HostArchitecture}
}

func stateName(stored string) string {
	if stored == "" {
		return ""
	}
	return "STATE_" + strings.ToUpper(stored)
}

func given(at time.Time) *timestamppb.Timestamp {
	if !at.After(epoch) {
		return nil
	}
	return timestamppb.New(at)
}
