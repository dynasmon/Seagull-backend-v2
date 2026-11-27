package auditstore

import "context"

const (
	ReasonUndecodable       = "undecodable"
	ReasonContractViolation = "contract_violation"
	ReasonMisplaced         = "misplaced"
)

// Declared here and not shared with the other stores: a capability says what it
// needs of a backbone it may not name, and the executable is the one place that
// knows the two line up.
type Record struct {
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
}

type Deliver func(ctx context.Context, records []Record) error

// The source advances its position only once a batch has been handled, so a
// crash chains the same records again, and the writer finds them chained.
type Source interface {
	Consume(ctx context.Context, deliver Deliver) error
}

// Head is a chain's newest entry and where the record it was chained from sits
// on the backbone.
type Head struct {
	Sequence  uint64
	Digest    []byte
	Partition int32
	Offset    int64
}

// The store is where every chain stands; the writer keeps nothing between
// batches. Chained answers, for each chain asked about, which of the event
// identifiers asked it holds and at what sequence.
type Store interface {
	Chained(ctx context.Context, asked map[string][]string) (map[string]map[string]uint64, error)
	Heads(ctx context.Context, chains []string) (map[string]Head, error)
	Append(ctx context.Context, rows []Row) error
}

type Refused struct {
	Key       []byte
	Value     []byte
	Reason    string
	Detail    string
	Partition int32
	Offset    int64
}

type Quarantine interface {
	Publish(ctx context.Context, refused []Refused) error
}
