package agentfinding

import "errors"

const (
	SchemaVersion    = 1
	MinSchemaVersion = 1
	MaxSchemaVersion = 1
)

// Every bound below is part of the agent finding contract, and what the backbone
// carries and the store holds are derived from these numbers.
const (
	IDLength        = 64
	MaxReports      = 4
	MaxTextLength   = 64
	MaxRouteLength  = 128
	MaxFindingBytes = 16 << 10
)

var ErrCursor = errors.New("the cursor is not one the platform issued")
