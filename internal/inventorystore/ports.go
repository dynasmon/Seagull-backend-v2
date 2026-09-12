package inventorystore

import "context"

const (
	ReasonUndecodable       = "undecodable"
	ReasonContractViolation = "contract_violation"
	ReasonUnstorable        = "unstorable"
)

// The fourth capability to declare these, and the reason to keep declaring them
// rather than share one: each says what *this* capability needs of a backbone it
// is not allowed to name, which is what makes the rule that a capability may not
// import another capability mean something.
type Record struct {
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
}

type Deliver func(ctx context.Context, records []Record) error

// The source advances its position only once a batch has been handled, so a
// crash folds the same records again instead of stepping over them.
type Source interface {
	Consume(ctx context.Context, deliver Deliver) error
}

// The items land before the scans, because a scan moves the line absence is
// measured against and a reader that saw the line move without the items would
// read a whole asset as having nothing installed.
type Sink interface {
	Store(ctx context.Context, rows []Row, scans []Scan) error
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
