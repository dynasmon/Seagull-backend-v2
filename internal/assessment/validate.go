package assessment

import (
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func Validate(assessed *assessmentv1.Assessment, now time.Time, policy event.Policy) error {
	if err := ValidateContract(assessed); err != nil {
		return err
	}
	return admissible(assessed.GetAssessedAt().AsTime(), now, policy)
}

// Every rule that does not depend on when the assessment is examined, so the
// projector reads back what the gateway admitted without refusing it for age.
func ValidateContract(assessed *assessmentv1.Assessment) error {
	if assessed == nil {
		return &event.Violation{Field: "assessment", Reason: "is missing"}
	}
	switch id := assessed.GetAssessmentId(); {
	case len(id) < MinAssessmentIDLength:
		return &event.Violation{Field: "assessment_id", Reason: fmt.Sprintf("is shorter than %d characters", MinAssessmentIDLength)}
	case len(id) > MaxAssessmentIDLength || !event.ValidIdentifier(id):
		return &event.Violation{Field: "assessment_id", Reason: "is malformed"}
	}
	if version := assessed.GetSchemaVersion(); version < MinSchemaVersion || version > MaxSchemaVersion {
		return &event.Violation{
			Field:  "schema_version",
			Reason: fmt.Sprintf("must be between %d and %d", MinSchemaVersion, MaxSchemaVersion),
		}
	}
	if !agentidentity.Valid(assessed.GetPolicyId()) {
		return &event.Violation{Field: "policy_id", Reason: "is missing or malformed"}
	}
	if revision := assessed.GetPolicyRevision(); revision == 0 || revision > math.MaxInt64 {
		return &event.Violation{Field: "policy_revision", Reason: fmt.Sprintf("must be between 1 and %d", int64(math.MaxInt64))}
	}
	if stamp := assessed.GetAssessedAt(); stamp == nil {
		return &event.Violation{Field: "assessed_at", Reason: "is missing"}
	} else if !stamp.IsValid() {
		return &event.Violation{Field: "assessed_at", Reason: "is not a representable instant"}
	}
	if err := event.ValidateOrigin(assessed.GetOrigin()); err != nil {
		return err
	}
	if err := event.ValidateCollection(assessed.GetCollection()); err != nil {
		return err
	}
	return validateResults(assessed.GetResults())
}

func validateResults(results []*assessmentv1.Result) error {
	if len(results) > MaxResults {
		return &event.Violation{
			Field:  "results",
			Reason: fmt.Sprintf("carries %d results and the ceiling is %d", len(results), MaxResults),
		}
	}
	seen := make(map[string]struct{}, len(results))
	for index, result := range results {
		field := fmt.Sprintf("results[%d]", index)
		id := result.GetCheckId()
		if !agentidentity.Valid(id) {
			return &event.Violation{Field: field + ".check_id", Reason: "is missing or malformed"}
		}
		if _, twice := seen[id]; twice {
			return &event.Violation{Field: field + ".check_id", Reason: "answers a check another result already answers"}
		}
		seen[id] = struct{}{}
		outcome := result.GetOutcome()
		if _, known := assessmentv1.Outcome_name[int32(outcome)]; !known || outcome == assessmentv1.Outcome_OUTCOME_UNSPECIFIED {
			return &event.Violation{Field: field + ".outcome", Reason: "is not an outcome the contract declares"}
		}
		if evidence := result.GetEvidence(); len(evidence) > MaxEvidenceLength || !utf8.ValidString(evidence) || strings.ContainsRune(evidence, 0) {
			return &event.Violation{Field: field + ".evidence", Reason: fmt.Sprintf("is not text of at most %d bytes", MaxEvidenceLength)}
		}
	}
	return nil
}

func admissible(assessed, now time.Time, policy event.Policy) error {
	if assessed.After(now.Add(policy.MaxClockSkew)) {
		return &event.Violation{
			Field:  "assessed_at",
			Reason: fmt.Sprintf("is more than %s ahead of the platform clock", policy.MaxClockSkew),
		}
	}
	if assessed.Before(now.Add(-policy.MaxAge)) {
		return &event.Violation{
			Field:  "assessed_at",
			Reason: fmt.Sprintf("is older than the %s admission window", policy.MaxAge),
		}
	}
	return nil
}

// The word an outcome is stored and counted under, such as `not_applicable`.
func OutcomeName(outcome assessmentv1.Outcome) string {
	return strings.ToLower(strings.TrimPrefix(outcome.String(), "OUTCOME_"))
}
