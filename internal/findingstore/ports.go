package findingstore

import "context"

const (
	ReasonUndecodable       = "undecodable"
	ReasonContractViolation = "contract_violation"
)

// Declared here and not shared with the other stores, for the reason they each
// declare their own: a capability says what it needs of a backbone it may not
// name, and the executable is the one place that knows the two line up.
type Record struct {
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
}

type Deliver func(ctx context.Context, records []Record) error

// The source advances its position only once a batch has been handled, so a
// crash writes the same decisions again instead of stepping over them.
type Source interface {
	Consume(ctx context.Context, deliver Deliver) error
}

// The findings land before the assessments they were decided in, so a reader
// that sees an assessment has already been able to see what it covered.
type Sink interface {
	Store(ctx context.Context, findings []FindingRow, assessments []AssessmentRow) error
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
