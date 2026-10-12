package agentstatus

import "time"

const (
	SchemaVersion    = 1
	MinSchemaVersion = 1
	MaxSchemaVersion = 1
)

// Every bound below is part of the status contract. The store's columns are
// derived from these numbers; they are not derived from a store.
const (
	MaxReportsPerBatch = 16

	MinInterval = 10 * time.Second
	MaxInterval = time.Hour

	MaxBootIDLength     = 64
	MaxNameLength       = 64
	MaxReasonLength     = 1024
	MaxVersionLength    = 128
	MaxRevisionLength   = 64
	MaxToolchainLength  = 32
	MaxPlatformLength   = 32
	MaxPolicyIDLength   = 64
	MaxAccountLength    = 64
	MaxCapabilityLength = 32
	MaxSeccompLength    = 32

	MaxComponents   = 32
	MaxModules      = 32
	MaxStreams      = 8
	MaxGroups       = 64
	MaxCapabilities = 64
)

// How late an agent's newest report may be, in the intervals that report
// announced, before the agent stops counting as active and before it counts as
// silent. One report lost on the way is still active; a run of them is late.
const (
	Allowance = 2
	Silence   = 5
)
