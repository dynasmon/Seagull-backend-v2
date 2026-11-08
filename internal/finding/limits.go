package finding

const (
	SchemaVersion    = 1
	MinSchemaVersion = 1
	MaxSchemaVersion = 1
)

// Every bound below is part of the findings contract, and what the backbone
// carries and the store holds are derived from these numbers. A CVE is told
// by a handful of advisories in one ecosystem, a few dozen where a kernel is
// fixed again and again, so a finding citing more is not one the platform made.
const (
	MaxCitations   = 256
	ItemIDLength   = 64
	MaxRecordBytes = 64 << 10
)
