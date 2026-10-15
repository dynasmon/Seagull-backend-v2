package assessmentstore

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

// What the store can hold of an instant, which is narrower than what the
// contract can say: outside these bounds UnixNano wraps silently.
var (
	earliest = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)
	latest   = time.Date(2262, time.April, 11, 23, 47, 16, 0, time.UTC)
)

// One assessment, kept beside every other one its agent made: the columns a
// reader asks about, what its checks found counted by outcome, and the
// assessment itself, byte for byte as the gateway published it, which is what a
// reader of one agent is handed back.
type Row struct {
	TenantID     string
	AgentID      string
	AssessmentID string
	IngestTime   time.Time

	AssessedAt     time.Time
	PolicyID       string
	PolicyRevision uint64

	Checks        uint32
	Passed        uint32
	Failed        uint32
	Errors        uint32
	Unsupported   uint32
	NotApplicable uint32

	Assessment []byte
}

func Project(assessed *assessmentv1.Assessment, published []byte) Row {
	row := Row{
		TenantID:     assessed.GetOrigin().GetTenantId(),
		AgentID:      assessed.GetOrigin().GetAgentId(),
		AssessmentID: assessed.GetAssessmentId(),
		IngestTime:   instant(assessed.GetReception().GetIngestTime()),

		AssessedAt:     instant(assessed.GetAssessedAt()),
		PolicyID:       assessed.GetPolicyId(),
		PolicyRevision: assessed.GetPolicyRevision(),

		Checks: uint32(len(assessed.GetResults())),

		Assessment: published,
	}
	for _, result := range assessed.GetResults() {
		switch result.GetOutcome() {
		case assessmentv1.Outcome_OUTCOME_PASS:
			row.Passed++
		case assessmentv1.Outcome_OUTCOME_FAIL:
			row.Failed++
		case assessmentv1.Outcome_OUTCOME_ERROR:
			row.Errors++
		case assessmentv1.Outcome_OUTCOME_UNSUPPORTED:
			row.Unsupported++
		case assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE:
			row.NotApplicable++
		}
	}
	return row
}

func instant(stamp *timestamppb.Timestamp) time.Time {
	if stamp == nil {
		return time.Time{}
	}
	return stamp.AsTime().UTC()
}

func storable(row Row) error {
	if row.IngestTime.IsZero() {
		return errors.New("reception.ingest_time is missing, so nothing says when the platform received the assessment")
	}
	for _, held := range []struct {
		field string
		at    time.Time
	}{
		{"reception.ingest_time", row.IngestTime},
		{"assessed_at", row.AssessedAt},
	} {
		if held.at.Before(earliest) || held.at.After(latest) {
			return fmt.Errorf("%s is outside the %s..%s the store can hold",
				held.field, earliest.Format(time.DateOnly), latest.Format(time.DateOnly))
		}
	}
	return nil
}
