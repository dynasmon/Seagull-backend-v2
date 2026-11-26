package auditstore

import "time"

// One entry of a chain: the entry itself, what a reader filters the trail by,
// where the backbone held the record it was chained from, and the event exactly
// as it was published, which is what the digest covers.
type Row struct {
	Chain    string
	Sequence uint64
	Previous []byte
	Digest   []byte

	EventID      string
	OccurredAt   time.Time
	Action       string
	ActorSubject string
	TargetID     string

	LogPartition int32
	LogOffset    int64

	Event []byte
}
