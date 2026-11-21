package fleetjudge

import (
	"context"
	"time"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Declared here and not shared, as every capability declares its own: it says
// what it needs of a backbone it may not name.
type Record struct {
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
	Timestamp time.Time
}

type Deliver func(ctx context.Context, records []Record) error

// A log the judge reads whole: everything written before it starts, and then
// whatever follows, so two judges reading one log hold the same state.
type Log interface {
	Replay(ctx context.Context, deliver Deliver) error
	Follow(ctx context.Context, deliver Deliver) error
}

// The status log also says how much of it the judge has not read, which is how
// it confirms it is reading the end, as a gateway confirms its roster (ADR 46).
type StatusLog interface {
	Log
	Behind(ctx context.Context) (int64, time.Time, error)
}

type Decisions interface {
	Publish(ctx context.Context, decided []*agentv1.Finding) error
}
