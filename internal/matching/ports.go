package matching

import (
	"context"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/finding"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// Declared here as each capability declares its own: what the matcher needs of
// a backbone it may not name, which the executable alone lines up.
type Record struct {
	Topic     string
	Partition int32
	Offset    int64
	Value     []byte
}

type Deliver func(ctx context.Context, records []Record) error

// One loop over both streams, advancing only once a batch is published, so a
// crash decides the same batch again instead of stepping over it.
type Source interface {
	Consume(ctx context.Context, deliver Deliver) error
}

// Where the owner of a stream stands: everything before a committed offset is
// in the owner's store.
type Positions interface {
	Committed(ctx context.Context, group, topic string) (map[int32]int64, error)
	Ends(ctx context.Context, topic string) (map[int32]int64, error)
}

type Asset struct {
	TenantID string
	AgentID  string
}

type Inventory interface {
	Asset(ctx context.Context, asset Asset) (finding.Asset, bool, error)
	Holders(ctx context.Context, packages []string) ([]Asset, error)
}

type Key struct {
	Ecosystem string
	Package   string
}

type Intelligence interface {
	Read(ctx context.Context, ecosystem string, packages []string) (finding.Intelligence, error)
	Before(ctx context.Context, source, id string, modified time.Time, normalization uint32) ([]Key, error)
}

type Findings interface {
	Decisions(ctx context.Context, asset Asset) (map[finding.Name]*vulnerabilityv1.Finding, error)
}

type Publisher interface {
	Publish(ctx context.Context, records []*vulnerabilityv1.FindingRecord) error
}
