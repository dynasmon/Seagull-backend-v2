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
	MaxGatewayLength     = 64

	MaxEventBytes = 960 << 10
)

// The longest every text the contract carries may be, by the path a rule and a
// violation name it with: what the platform makes out of an event's text, a
// detection above all, weighs what these allow and no more.
var longest = map[string]int{
	"event_id":                              MaxEventIDLength,
	"origin.tenant_id":                      MaxTenantIDLength,
	"origin.agent_id":                       MaxAgentIDLength,
	"origin.host.hostname":                  MaxHostnameLength,
	"origin.host.ip":                        MaxAddressLength,
	"origin.host.os":                        MaxOperatingSystem,
	"origin.host.architecture":              MaxArchitectureLen,
	"collection.collector":                  MaxCollectorLength,
	"collection.source":                     MaxSourceLength,
	"reception.gateway":                     MaxGatewayLength,
	"reception.batch_id":                    MaxBatchIDLength,
	"authentication.outcome_reason":         MaxOutcomeReasonLen,
	"authentication.method":                 MaxAuthMethodLength,
	"authentication.user.name":              MaxUserNameLength,
	"authentication.user.domain":            MaxUserDomainLength,
	"authentication.user.uid":               MaxUserIDLength,
	"authentication.service.name":           MaxServiceNameLength,
	"authentication.service.protocol":       MaxProtocolLength,
	"authentication.network.source.ip":      MaxAddressLength,
	"authentication.network.destination.ip": MaxAddressLength,
	"authentication.raw_record":             MaxRawRecordLength,
}

func LongestText(field string) (int, bool) {
	most, bounded := longest[field]
	return most, bounded
}
