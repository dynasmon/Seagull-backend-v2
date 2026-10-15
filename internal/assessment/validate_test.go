package assessment

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

var assessedAt = time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)

var window = event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 720 * time.Hour}

func assessed() *assessmentv1.Assessment {
	return &assessmentv1.Assessment{
		AssessmentId:   "7d3f2a1b-4c5e-8f6a-9b0c-1d2e3f4a5b6c",
		SchemaVersion:  SchemaVersion,
		PolicyId:       "linux-web",
		PolicyRevision: 7,
		AssessedAt:     timestamppb.New(assessedAt),
		Origin: &eventv1.Origin{
			AgentId:  "web-01",
			TenantId: "acme",
			Host:     &eventv1.Host{Hostname: "web-01", Os: "linux", Architecture: "amd64"},
		},
		Collection: &eventv1.Collection{Collector: "assessment"},
		Results: []*assessmentv1.Result{
			{CheckId: "ssh.root-login", Outcome: assessmentv1.Outcome_OUTCOME_FAIL, Evidence: "PermitRootLogin is yes in /etc/ssh/sshd_config"},
			{CheckId: "shadow.permissions", Outcome: assessmentv1.Outcome_OUTCOME_PASS, Evidence: "0640 0:42"},
			{CheckId: "cramfs.disabled", Outcome: assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE},
		},
	}
}

func changed(change func(*assessmentv1.Assessment)) *assessmentv1.Assessment {
	held := assessed()
	change(held)
	return held
}

func TestAWellFormedAssessmentIsAdmitted(t *testing.T) {
	if err := Validate(assessed(), assessedAt, window); err != nil {
		t.Fatalf("a well formed assessment was refused: %v", err)
	}
	if err := Validate(changed(func(a *assessmentv1.Assessment) { a.Results = nil }), assessedAt, window); err != nil {
		t.Fatalf("an assessment saying its policy asks for no checks was refused: %v", err)
	}
	if err := Validate(changed(func(a *assessmentv1.Assessment) { a.Origin.Host = nil }), assessedAt, window); err != nil {
		t.Fatalf("an assessment that names no host was refused: %v", err)
	}
}

func TestAnAssessmentIsRefusedNamingTheFieldAtFault(t *testing.T) {
	for name, one := range map[string]struct {
		assessment *assessmentv1.Assessment
		field      string
	}{
		"no identifier":        {changed(func(a *assessmentv1.Assessment) { a.AssessmentId = "" }), "assessment_id"},
		"short identifier":     {changed(func(a *assessmentv1.Assessment) { a.AssessmentId = "abc" }), "assessment_id"},
		"malformed identifier": {changed(func(a *assessmentv1.Assessment) { a.AssessmentId = "not an identifier" }), "assessment_id"},
		"long identifier":      {changed(func(a *assessmentv1.Assessment) { a.AssessmentId = strings.Repeat("a", MaxAssessmentIDLength+1) }), "assessment_id"},
		"schema version":       {changed(func(a *assessmentv1.Assessment) { a.SchemaVersion = MaxSchemaVersion + 1 }), "schema_version"},
		"no policy":            {changed(func(a *assessmentv1.Assessment) { a.PolicyId = "" }), "policy_id"},
		"malformed policy":     {changed(func(a *assessmentv1.Assessment) { a.PolicyId = "linux web" }), "policy_id"},
		"no revision":          {changed(func(a *assessmentv1.Assessment) { a.PolicyRevision = 0 }), "policy_revision"},
		"unstorable revision":  {changed(func(a *assessmentv1.Assessment) { a.PolicyRevision = math.MaxInt64 + 1 }), "policy_revision"},
		"no assessed at":       {changed(func(a *assessmentv1.Assessment) { a.AssessedAt = nil }), "assessed_at"},
		"invalid assessed at":  {changed(func(a *assessmentv1.Assessment) { a.AssessedAt = &timestamppb.Timestamp{Nanos: -1} }), "assessed_at"},
		"no origin":            {changed(func(a *assessmentv1.Assessment) { a.Origin = nil }), "origin"},
		"no agent":             {changed(func(a *assessmentv1.Assessment) { a.Origin.AgentId = "" }), "origin.agent_id"},
		"no tenant":            {changed(func(a *assessmentv1.Assessment) { a.Origin.TenantId = "" }), "origin.tenant_id"},
		"no collection":        {changed(func(a *assessmentv1.Assessment) { a.Collection = nil }), "collection"},
		"no collector":         {changed(func(a *assessmentv1.Assessment) { a.Collection.Collector = "" }), "collection.collector"},
		"no check":             {changed(func(a *assessmentv1.Assessment) { a.Results[1].CheckId = "" }), "results[1].check_id"},
		"malformed check":      {changed(func(a *assessmentv1.Assessment) { a.Results[1].CheckId = "ssh root" }), "results[1].check_id"},
		"check answered twice": {changed(func(a *assessmentv1.Assessment) { a.Results[2].CheckId = "ssh.root-login" }), "results[2].check_id"},
		"unspecified outcome":  {changed(func(a *assessmentv1.Assessment) { a.Results[0].Outcome = assessmentv1.Outcome_OUTCOME_UNSPECIFIED }), "results[0].outcome"},
		"undeclared outcome":   {changed(func(a *assessmentv1.Assessment) { a.Results[0].Outcome = assessmentv1.Outcome(42) }), "results[0].outcome"},
		"long evidence":        {changed(func(a *assessmentv1.Assessment) { a.Results[0].Evidence = strings.Repeat("e", MaxEvidenceLength+1) }), "results[0].evidence"},
		"evidence with a nul":  {changed(func(a *assessmentv1.Assessment) { a.Results[0].Evidence = "yes\x00" }), "results[0].evidence"},
		"from the future":      {changed(func(a *assessmentv1.Assessment) { a.AssessedAt = timestamppb.New(assessedAt.Add(time.Hour)) }), "assessed_at"},
		"too long ago":         {changed(func(a *assessmentv1.Assessment) { a.AssessedAt = timestamppb.New(assessedAt.Add(-31 * 24 * time.Hour)) }), "assessed_at"},
	} {
		t.Run(name, func(t *testing.T) {
			err := Validate(one.assessment, assessedAt, window)
			var violation *event.Violation
			if !errors.As(err, &violation) {
				t.Fatalf("the assessment was refused without naming a field, or admitted: %v", err)
			}
			if violation.Field != one.field {
				t.Errorf("the refusal names %s and the fault is in %s", violation.Field, one.field)
			}
		})
	}
}

func TestAnAssessmentAnswersAtMostAsManyChecksAsAChecklistHolds(t *testing.T) {
	results := func(count int) []*assessmentv1.Result {
		held := make([]*assessmentv1.Result, count)
		for index := range held {
			held[index] = &assessmentv1.Result{CheckId: fmt.Sprintf("check-%d", index), Outcome: assessmentv1.Outcome_OUTCOME_PASS}
		}
		return held
	}
	if err := ValidateContract(changed(func(a *assessmentv1.Assessment) { a.Results = results(MaxResults) })); err != nil {
		t.Fatalf("an assessment answering %d checks was refused: %v", MaxResults, err)
	}
	err := ValidateContract(changed(func(a *assessmentv1.Assessment) { a.Results = results(MaxResults + 1) }))
	var violation *event.Violation
	if !errors.As(err, &violation) || violation.Field != "results" {
		t.Fatalf("an assessment answering %d checks was not refused over its results: %v", MaxResults+1, err)
	}
}

func TestTheContractHoldsWhateverTheClockSays(t *testing.T) {
	old := changed(func(a *assessmentv1.Assessment) {
		a.AssessedAt = timestamppb.New(assessedAt.Add(-365 * 24 * time.Hour))
	})
	if err := ValidateContract(old); err != nil {
		t.Fatalf("an assessment the gateway admitted long ago was refused by the contract alone: %v", err)
	}
}

func TestAnOutcomeIsNamedInOneWord(t *testing.T) {
	for outcome, word := range map[assessmentv1.Outcome]string{
		assessmentv1.Outcome_OUTCOME_PASS:           "pass",
		assessmentv1.Outcome_OUTCOME_FAIL:           "fail",
		assessmentv1.Outcome_OUTCOME_ERROR:          "error",
		assessmentv1.Outcome_OUTCOME_UNSUPPORTED:    "unsupported",
		assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE: "not_applicable",
	} {
		if named := OutcomeName(outcome); named != word {
			t.Errorf("%s is named %q, not %q", outcome, named, word)
		}
	}
}
