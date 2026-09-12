package inventory

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func Validate(record *inventoryv1.Record, now time.Time, policy event.Policy) error {
	if err := ValidateContract(record); err != nil {
		return err
	}
	return admissible(record.GetCollectedAt().AsTime(), now, policy)
}

// Every rule that does not depend on when the record is examined, so a replay
// reprocesses what it exists to reprocess rather than refusing it for age.
func ValidateContract(record *inventoryv1.Record) error {
	if record == nil {
		return &event.Violation{Field: "record", Reason: "is missing"}
	}

	if err := recordID(record.GetRecordId()); err != nil {
		return err
	}
	if version := record.GetSchemaVersion(); version < MinSchemaVersion || version > MaxSchemaVersion {
		return &event.Violation{
			Field:  "schema_version",
			Reason: fmt.Sprintf("must be between %d and %d", MinSchemaVersion, MaxSchemaVersion),
		}
	}
	if err := validateKind(record.GetKind()); err != nil {
		return err
	}
	if err := declared("mode", int32(record.GetMode()), inventoryv1.Mode_name); err != nil {
		return err
	}
	if collected := record.GetCollectedAt(); collected == nil {
		return &event.Violation{Field: "collected_at", Reason: "is missing"}
	} else if !collected.IsValid() {
		return &event.Violation{Field: "collected_at", Reason: "is not a representable instant"}
	}
	if err := event.ValidateOrigin(record.GetOrigin()); err != nil {
		return err
	}
	if err := event.ValidateCollection(record.GetCollection()); err != nil {
		return err
	}
	return validateItems(record)
}

// A kind the contract declares but this build cannot identify an item of is
// refused rather than stored under one shared identity, which would fold an
// asset's whole inventory of that kind into a single row.
func validateKind(kind inventoryv1.Kind) error {
	if err := declared("kind", int32(kind), inventoryv1.Kind_name); err != nil {
		return err
	}
	if !Shaped(kind) {
		return &event.Violation{Field: "kind", Reason: "is not a kind this build knows how to identify an item of"}
	}
	return nil
}

func admissible(collected, now time.Time, policy event.Policy) error {
	if collected.After(now.Add(policy.MaxClockSkew)) {
		return &event.Violation{
			Field:  "collected_at",
			Reason: fmt.Sprintf("is more than %s ahead of the platform clock", policy.MaxClockSkew),
		}
	}
	if collected.Before(now.Add(-policy.MaxAge)) {
		return &event.Violation{
			Field:  "collected_at",
			Reason: fmt.Sprintf("is older than the %s admission window", policy.MaxAge),
		}
	}
	return nil
}

// An empty snapshot is how a collector says the asset has nothing of this kind,
// so it is admitted; an empty delta states nothing at all and is refused.
func validateItems(record *inventoryv1.Record) error {
	items := record.GetItems()
	kind := record.GetKind()

	if len(items) == 0 && record.GetMode() == inventoryv1.Mode_MODE_DELTA {
		return &event.Violation{Field: "items", Reason: "is empty and a delta states nothing"}
	}
	if len(items) > MaxItemsPerRecord {
		return &event.Violation{
			Field:  "items",
			Reason: fmt.Sprintf("carries %d items and the ceiling is %d", len(items), MaxItemsPerRecord),
		}
	}
	if Singleton(kind) && len(items) > 1 {
		return &event.Violation{
			Field:  "items",
			Reason: fmt.Sprintf("carries %d items and an asset has at most one %s", len(items), KindName(kind)),
		}
	}

	for index, item := range items {
		if err := validateItem(kind, item, index); err != nil {
			return err
		}
	}
	return nil
}

func validateItem(kind inventoryv1.Kind, item *inventoryv1.Item, index int) error {
	field := fmt.Sprintf("items[%d]", index)
	if !shapes[kind].present(item) {
		return &event.Violation{Field: field, Reason: "carries no " + KindName(kind) + ", which is what this record declares"}
	}

	switch kind {
	case inventoryv1.Kind_KIND_OPERATING_SYSTEM:
		return validateOperatingSystem(field, item.GetOperatingSystem())
	case inventoryv1.Kind_KIND_KERNEL:
		return validateKernel(field, item.GetKernel())
	case inventoryv1.Kind_KIND_PACKAGE:
		return validatePackage(field, item.GetPackage())
	case inventoryv1.Kind_KIND_SERVICE:
		return validateService(field, item.GetService())
	case inventoryv1.Kind_KIND_NETWORK_INTERFACE:
		return validateNetworkInterface(field, item.GetNetworkInterface())
	case inventoryv1.Kind_KIND_USER:
		return validateUser(field, item.GetUser())
	case inventoryv1.Kind_KIND_HARDWARE:
		return validateHardware(field, item.GetHardware())
	case inventoryv1.Kind_KIND_PROCESS:
		return validateProcess(field, item.GetProcess())
	default:
		return &event.Violation{Field: "kind", Reason: "is unspecified or unknown"}
	}
}

func validateOperatingSystem(field string, operating *inventoryv1.OperatingSystem) error {
	if err := text(field+".operating_system.name", operating.GetName(), MaxNameLength, true); err != nil {
		return err
	}
	if err := text(field+".operating_system.version", operating.GetVersion(), MaxVersionLength, false); err != nil {
		return err
	}
	if err := text(field+".operating_system.build", operating.GetBuild(), MaxBuildLength, false); err != nil {
		return err
	}
	if err := text(field+".operating_system.platform", operating.GetPlatform(), MaxPlatformLength, false); err != nil {
		return err
	}
	if err := text(field+".operating_system.codename", operating.GetCodename(), MaxCodenameLength, false); err != nil {
		return err
	}
	return text(field+".operating_system.family", operating.GetFamily(), MaxFamilyLength, false)
}

func validateKernel(field string, kernel *inventoryv1.Kernel) error {
	if err := text(field+".kernel.name", kernel.GetName(), MaxNameLength, true); err != nil {
		return err
	}
	if err := text(field+".kernel.release", kernel.GetRelease(), MaxReleaseLength, false); err != nil {
		return err
	}
	if err := text(field+".kernel.version", kernel.GetVersion(), MaxVersionLength, false); err != nil {
		return err
	}
	return text(field+".kernel.architecture", kernel.GetArchitecture(), MaxArchitectureLength, false)
}

func validatePackage(field string, installed *inventoryv1.Package) error {
	if err := text(field+".package.name", installed.GetName(), MaxNameLength, true); err != nil {
		return err
	}
	if err := text(field+".package.version", installed.GetVersion(), MaxVersionLength, false); err != nil {
		return err
	}
	if err := text(field+".package.architecture", installed.GetArchitecture(), MaxArchitectureLength, false); err != nil {
		return err
	}
	if err := text(field+".package.manager", installed.GetManager(), MaxManagerLength, false); err != nil {
		return err
	}
	if err := text(field+".package.source", installed.GetSource(), MaxSourceLength, false); err != nil {
		return err
	}
	if err := text(field+".package.vendor", installed.GetVendor(), MaxVendorLength, false); err != nil {
		return err
	}
	return instant(field+".package.installed_at", installed.GetInstalledAt() != nil, installed.GetInstalledAt().IsValid())
}

func validateService(field string, service *inventoryv1.Service) error {
	if err := text(field+".service.name", service.GetName(), MaxNameLength, true); err != nil {
		return err
	}
	if err := text(field+".service.display_name", service.GetDisplayName(), MaxDisplayNameLength, false); err != nil {
		return err
	}
	if err := named(field+".service.state", int32(service.GetState()), inventoryv1.Service_State_name); err != nil {
		return err
	}
	if err := text(field+".service.start_mode", service.GetStartMode(), MaxStartModeLength, false); err != nil {
		return err
	}
	return text(field+".service.path", service.GetPath(), MaxPathLength, false)
}

func validateNetworkInterface(field string, adapter *inventoryv1.NetworkInterface) error {
	if err := text(field+".network_interface.name", adapter.GetName(), MaxNameLength, true); err != nil {
		return err
	}
	if err := text(field+".network_interface.mac", adapter.GetMac(), MaxMACLength, false); err != nil {
		return err
	}
	addresses := adapter.GetAddresses()
	if len(addresses) > MaxAddressesPerInterface {
		return &event.Violation{
			Field:  field + ".network_interface.addresses",
			Reason: fmt.Sprintf("carries %d addresses and the ceiling is %d", len(addresses), MaxAddressesPerInterface),
		}
	}
	for index, value := range addresses {
		if err := interfaceAddress(fmt.Sprintf("%s.network_interface.addresses[%d]", field, index), value); err != nil {
			return err
		}
	}
	if err := named(field+".network_interface.state", int32(adapter.GetState()), inventoryv1.NetworkInterface_State_name); err != nil {
		return err
	}
	return text(field+".network_interface.type", adapter.GetType(), MaxTypeLength, false)
}

func validateUser(field string, account *inventoryv1.User) error {
	if err := text(field+".user.name", account.GetName(), MaxNameLength, true); err != nil {
		return err
	}
	if err := text(field+".user.uid", account.GetUid(), MaxAccountIDLength, false); err != nil {
		return err
	}
	if err := text(field+".user.gid", account.GetGid(), MaxAccountIDLength, false); err != nil {
		return err
	}
	if err := text(field+".user.home", account.GetHome(), MaxPathLength, false); err != nil {
		return err
	}
	if err := text(field+".user.shell", account.GetShell(), MaxPathLength, false); err != nil {
		return err
	}
	groups := account.GetGroups()
	if len(groups) > MaxGroupsPerUser {
		return &event.Violation{
			Field:  field + ".user.groups",
			Reason: fmt.Sprintf("carries %d groups and the ceiling is %d", len(groups), MaxGroupsPerUser),
		}
	}
	for index, group := range groups {
		if err := text(fmt.Sprintf("%s.user.groups[%d]", field, index), group, MaxNameLength, true); err != nil {
			return err
		}
	}
	return instant(field+".user.last_login", account.GetLastLogin() != nil, account.GetLastLogin().IsValid())
}

func validateHardware(field string, hardware *inventoryv1.Hardware) error {
	if err := text(field+".hardware.cpu_name", hardware.GetCpuName(), MaxNameLength, false); err != nil {
		return err
	}
	if err := text(field+".hardware.serial", hardware.GetSerial(), MaxSerialLength, false); err != nil {
		return err
	}
	if err := text(field+".hardware.vendor", hardware.GetVendor(), MaxVendorLength, false); err != nil {
		return err
	}
	return text(field+".hardware.model", hardware.GetModel(), MaxModelLength, false)
}

func validateProcess(field string, running *inventoryv1.Process) error {
	if err := text(field+".process.name", running.GetName(), MaxNameLength, true); err != nil {
		return err
	}
	if err := text(field+".process.path", running.GetPath(), MaxPathLength, false); err != nil {
		return err
	}
	if err := text(field+".process.command_line", running.GetCommandLine(), MaxCommandLineLength, false); err != nil {
		return err
	}
	if err := text(field+".process.user", running.GetUser(), MaxNameLength, false); err != nil {
		return err
	}
	return instant(field+".process.started_at", running.GetStartedAt() != nil, running.GetStartedAt().IsValid())
}

func recordID(value string) error {
	if len(value) < MinRecordIDLength {
		return &event.Violation{
			Field:  "record_id",
			Reason: fmt.Sprintf("is shorter than %d characters", MinRecordIDLength),
		}
	}
	if !event.ValidIdentifier(value) {
		return &event.Violation{Field: "record_id", Reason: "is malformed"}
	}
	return nil
}

func instant(field string, present, valid bool) error {
	if present && !valid {
		return &event.Violation{Field: field, Reason: "is not a representable instant"}
	}
	return nil
}

func declared(field string, value int32, names map[int32]string) error {
	if value == 0 {
		return &event.Violation{Field: field, Reason: "is unspecified"}
	}
	return named(field, value, names)
}

// What a record is and what may be concluded from it have to be stated, and a
// collector that could not read a service's state has observed that it could
// not: an unspecified enum is admitted where the platform draws no conclusion
// from it, and a number no build declares is refused either way, because the
// store keeps the name of a value and would read that one back as unspecified.
func named(field string, value int32, names map[int32]string) error {
	if _, declared := names[value]; !declared {
		return &event.Violation{Field: field, Reason: "is not a value the contract declares"}
	}
	return nil
}

func text(field, value string, maximum int, required bool) error {
	if value == "" {
		if required {
			return &event.Violation{Field: field, Reason: "is required"}
		}
		return nil
	}
	if len(value) > maximum {
		return &event.Violation{Field: field, Reason: fmt.Sprintf("is longer than %d bytes", maximum)}
	}
	return nil
}

// An address or an address and its prefix length, because that is how an
// interface holds one and splitting them would make a collector guess.
func interfaceAddress(field, value string) error {
	if value == "" {
		return &event.Violation{Field: field, Reason: "is required"}
	}
	if len(value) > MaxInterfaceAddressLength {
		return &event.Violation{
			Field:  field,
			Reason: fmt.Sprintf("is longer than %d bytes", MaxInterfaceAddressLength),
		}
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(value); err != nil {
		return &event.Violation{Field: field, Reason: "is not an IP address or prefix"}
	}
	return nil
}
