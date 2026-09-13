package advisorystore

import "context"

const (
	ReasonUndecodable       = "undecodable"
	ReasonContractViolation = "contract_violation"
)

// What this capability needs of a backbone it is not allowed to name, declared
// here rather than shared with the other stores: the rule that a capability may
// not import another only means something if each says what it needs itself.
type Record struct {
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
}

type Deliver func(ctx context.Context, records []Record) error

// The source advances its position only once a batch has been handled, so a
// crash writes the same records again instead of stepping over them.
type Source interface {
	Consume(ctx context.Context, deliver Deliver) error
}

type Sink interface {
	Store(ctx context.Context, projected Projection) error
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
