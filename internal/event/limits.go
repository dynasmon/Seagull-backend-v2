package event

const (
	SchemaVersion    = 1
	MinSchemaVersion = 1
	MaxSchemaVersion = 1
)

// Every bound below is part of the event contract. Storage schemas are derived
// from these numbers; they are not derived from a storage schema, and what the
// backbone carries is derived from the bytes an event encodes to as the gateway
// publishes it.
const (
	MaxEventIDLength     = 64
	MinEventIDLength     = 8
	MaxTenantIDLength    = 64
	MaxAgentIDLength     = 64
	MaxHostnameLength    = 255
	MaxAddressLength     = 45
	MaxOperatingSystem   = 128
	MaxArchitectureLen   = 32
	MaxCollectorLength   = 64
	MaxSourceLength      = 512
	MaxUserNameLength    = 256
	MaxUserDomainLength  = 255
	MaxUserIDLength      = 64
	MaxServiceNameLength = 64
	MaxProtocolLength    = 32
	MaxOutcomeReasonLen  = 64
	MaxAuthMethodLength  = 32
	MaxRawRecordLength   = 4096
	MaxBatchIDLength     = 64

	MaxEventBytes = 960 << 10
)
