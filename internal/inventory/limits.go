package inventory

import "github.com/dynasmon/Seagull-backend-v2/internal/event"

const (
	SchemaVersion    = 1
	MinSchemaVersion = 1
	MaxSchemaVersion = 1
)

// Every bound below is part of the inventory contract. Storage schemas are
// derived from these numbers; they are not derived from a storage schema.
const (
	MaxRecordIDLength = 64
	MinRecordIDLength = 8

	// A fat server reports a few thousand packages, which is the widest kind by
	// far. The ceilings bound what one request can make the gateway hold before
	// the body ceiling does, so a producer cannot buy memory with item counts.
	MaxItemsPerRecord = 10_000
	MaxItemsPerBatch  = 20_000

	MaxNameLength         = 256
	MaxVersionLength      = 128
	MaxArchitectureLength = 32
	MaxManagerLength      = 32
	MaxSourceLength       = 256
	MaxVendorLength       = 256
	MaxPathLength         = 4096
	MaxCommandLineLength  = 8192
	MaxDisplayNameLength  = 256
	MaxStartModeLength    = 32
	MaxBuildLength        = 128
	MaxPlatformLength     = 64
	MaxCodenameLength     = 64
	MaxFamilyLength       = 32
	MaxReleaseLength      = 128
	MaxSerialLength       = 128
	MaxModelLength        = 256
	MaxTypeLength         = 32

	// A Windows security identifier reaches 184 characters, which is what this
	// bound is for: a POSIX uid needs eight.
	MaxAccountIDLength = 192

	// An address or an address and its prefix length: `/128` is four bytes
	// wider than the widest address the event contract bounds.
	MaxInterfaceAddressLength = event.MaxAddressLength + 4

	MaxMACLength             = 64
	MaxAddressesPerInterface = 64
	MaxGroupsPerUser         = 256
)
