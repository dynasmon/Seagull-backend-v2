package audit

const (
	SchemaVersion    = 1
	MinSchemaVersion = 1
	MaxSchemaVersion = 1
)

// Every bound below is part of the audit contract, and what the backbone carries
// and the store holds are derived from these numbers. The contract states the
// ones a reviewer reads; the rest bound what a component may say about itself.
const (
	MaxEventIDLength   = 64
	MaxSubjectLength   = 256
	MaxSessionIDLength = 64
	MaxTargetIDLength  = 256
	MaxCodeLength      = 64
	MaxReasonLength    = 1024
	MaxComponentLength = 64
	MaxRequestIDLength = 128
	MaxAddressLength   = 64
	MaxChangeLength    = 256
	MaxDatasetLength   = 64
	MaxEventBytes      = 4 << 10
)
