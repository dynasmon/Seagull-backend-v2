package auditstore

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/audit"
	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
)

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

func project(entry *auditv1.Entry, recorded *auditv1.Event, record Record) Row {
	return Row{
		Chain:    entry.GetChain(),
		Sequence: entry.GetSequence(),
		Previous: entry.GetPrevious(),
		Digest:   entry.GetDigest(),

		EventID:      recorded.GetEventId(),
		OccurredAt:   recorded.GetOccurredAt().AsTime().UTC(),
		Action:       audit.ActionName(recorded.GetAction()),
		ActorSubject: recorded.GetActor().GetSubject(),
		TargetID:     recorded.GetTarget().GetId(),

		LogPartition: record.Partition,
		LogOffset:    record.Offset,

		Event: entry.GetEvent(),
	}
}
