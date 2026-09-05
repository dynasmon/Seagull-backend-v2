package broker

import "github.com/dynasmon/Seagull-backend-v2/internal/detection"

// What a record on the event stream is keyed by, and therefore what the
// backbone keeps together. A reader admits a stateful rule on the strength of
// this, so changing the key without changing this splits state silently.
var PartitionedBy = []detection.Field{"origin.agent_id"}
