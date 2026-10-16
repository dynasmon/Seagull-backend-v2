package assessment

const (
	SchemaVersion    = 1
	MinSchemaVersion = 1
	MaxSchemaVersion = 1
)

// Every bound below is part of the assessment contract. The store's columns are
// derived from these numbers; they are not derived from a store.
const (
	MaxChecks              = 512
	MaxResults             = MaxChecks
	MaxAssessmentsPerBatch = 16

	MaxCheckIDLength      = 64
	MaxTitleLength        = 256
	MaxEvidenceLength     = 512
	MinAssessmentIDLength = 8
	MaxAssessmentIDLength = 64
	MaxPolicyIDLength     = 64

	MaxPathLength      = 4096
	MaxGroupLength     = 64
	MaxParameterLength = 255
	MaxModuleLength    = 55
	MaxPackageLength   = 255
	MaxUnitLength      = 255
	MaxDirectiveLength = 64

	MaxValues               = 16
	MaxParameterValueLength = 128
	MaxDirectiveValueLength = 256

	MaxPermissions = 0o7777
)

// The places a file check may not look: what the kernel and running services
// make up rather than what a host is configured with, and what an agent's own
// service may be shown differently from the host.
var Unexamined = []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"}
