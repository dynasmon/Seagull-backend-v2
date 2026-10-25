package ingest_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/assessment"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type recordingAssessments struct {
	published [][]*assessmentv1.Assessment
	failure   error
}

func (r *recordingAssessments) PublishAssessments(_ context.Context, assessments []*assessmentv1.Assessment) error {
	if r.failure != nil {
		return r.failure
	}
	r.published = append(r.published, assessments)
	return nil
}

func (r *recordingAssessments) last() []*assessmentv1.Assessment {
	if len(r.published) == 0 {
		return nil
	}
	return r.published[len(r.published)-1]
}

func newAssessmentAdmitter(t *testing.T, backbone ingest.AssessmentBackbone) *ingest.AssessmentAdmitter {
	t.Helper()
	admitter, err := ingest.NewAssessmentAdmitter(
		backbone,
		ingest.AssessmentPolicy{
			Gateway:                "gateway-a",
			MaxAssessmentsPerBatch: 2,
			Assessment:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 720 * time.Hour},
		},
		ingest.NewAssessmentMetrics(metrics.New("test")),
		ingest.WithAssessmentClock(func() time.Time { return admissionClock }),
	)
	if err != nil {
		t.Fatalf("build assessment admitter: %v", err)
	}
	return admitter
}

func posture() *assessmentv1.Assessment {
	return fixtures.Posture{At: admissionClock.Add(-time.Minute)}.Assessment()
}

func TestAnAdmittedAssessmentBatchIsAcknowledgedAsDurable(t *testing.T) {
	backbone := &recordingAssessments{}
	admitter := newAssessmentAdmitter(t, backbone)

	acknowledgement, err := admitter.Admit(context.Background(), identity(), "acme", fixtures.AssessmentBatch("assessment-1", posture()))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if !acknowledgement.GetAccepted() || !acknowledgement.GetDurable() || acknowledgement.GetReceived() != 1 {
		t.Fatalf("an admitted assessment must be acknowledged as durable and counted: %+v", acknowledgement)
	}
	if len(backbone.last()) != 1 {
		t.Fatalf("expected 1 published assessment, got %d", len(backbone.last()))
	}
}

// A weakened host could otherwise be made to look hardened by an agent filing
// its findings under another agent or another estate.
func TestAnAssessmentIsStampedWithTheVerifiedAgentTheRegistryTenantAndThePlatformClock(t *testing.T) {
	backbone := &recordingAssessments{}
	admitter := newAssessmentAdmitter(t, backbone)

	impersonating := posture()
	impersonating.Origin.AgentId = "domain-controller"
	impersonating.Origin.TenantId = "someone-else"
	impersonating.Reception = &eventv1.Reception{Gateway: "not-a-gateway", BatchId: "not-this-batch"}
	claimingNothing := fixtures.Posture{AssessmentID: "asm-0000000002", At: admissionClock}.Assessment()
	claimingNothing.Origin = nil

	if _, err := admitter.Admit(context.Background(), identity(), "globex", fixtures.AssessmentBatch("assessment-7", impersonating, claimingNothing)); err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	for index, published := range backbone.last() {
		if published.GetOrigin().GetAgentId() != "web-01" || published.GetOrigin().GetTenantId() != "globex" {
			t.Errorf("assessment %d speaks for %q in %q", index, published.GetOrigin().GetAgentId(), published.GetOrigin().GetTenantId())
		}
		reception := published.GetReception()
		if reception.GetGateway() != "gateway-a" || reception.GetBatchId() != "assessment-7" || !reception.GetIngestTime().AsTime().Equal(admissionClock) {
			t.Errorf("assessment %d kept a reception the platform did not write: %+v", index, reception)
		}
	}
}

func TestAnAssessmentBatchIsBoundedAndNamesTheAssessmentItRefuses(t *testing.T) {
	broken := posture()
	broken.Results[2].Evidence = strings.Repeat("e", assessment.MaxEvidenceLength+1)
	unsupported := fixtures.AssessmentBatch("assessment-1", posture())
	unsupported.ProtocolVersion = 99
	unanswered := posture()
	unanswered.Results[1].Outcome = assessmentv1.Outcome_OUTCOME_UNSPECIFIED

	for name, one := range map[string]struct {
		batch *assessmentv1.AssessmentBatch
		code  ingest.RejectionCode
		index int
		field string
	}{
		"empty":           {fixtures.AssessmentBatch("assessment-1"), ingest.CodeEmptyBatch, -1, ""},
		"too many":        {fixtures.AssessmentBatch("assessment-1", posture(), posture(), posture()), ingest.CodeBatchTooLarge, -1, ""},
		"no batch id":     {fixtures.AssessmentBatch("", posture()), ingest.CodeMalformedBatchID, -1, "batch_id"},
		"protocol":        {unsupported, ingest.CodeUnsupportedProtocol, -1, ""},
		"long evidence":   {fixtures.AssessmentBatch("assessment-1", posture(), broken), ingest.CodeInvalidAssessment, 1, "results[2].evidence"},
		"no outcome":      {fixtures.AssessmentBatch("assessment-1", unanswered), ingest.CodeInvalidAssessment, 0, "results[1].outcome"},
		"from the future": {fixtures.AssessmentBatch("assessment-1", fixtures.Posture{At: admissionClock.Add(time.Hour)}.Assessment()), ingest.CodeInvalidAssessment, 0, "assessed_at"},
		"too old": {fixtures.AssessmentBatch("assessment-1", fixtures.Posture{At: admissionClock.Add(-721 * time.Hour)}.Assessment()),
			ingest.CodeInvalidAssessment, 0, "assessed_at"},
		"no revision": {fixtures.AssessmentBatch("assessment-1", func() *assessmentv1.Assessment {
			held := posture()
			held.PolicyRevision = 0
			return held
		}()), ingest.CodeInvalidAssessment, 0, "policy_revision"},
	} {
		t.Run(name, func(t *testing.T) {
			backbone := &recordingAssessments{}
			_, err := newAssessmentAdmitter(t, backbone).Admit(context.Background(), identity(), "acme", one.batch)
			rejection := rejectionOf(t, err)
			if rejection.Code != one.code || rejection.EventIndex != one.index || rejection.Field != one.field {
				t.Fatalf("refused with %q at %d naming %q", rejection.Code, rejection.EventIndex, rejection.Field)
			}
			if len(backbone.published) != 0 {
				t.Fatal("a refused batch reached the backbone")
			}
		})
	}
}

func TestAnAssessmentBatchTheBackboneRefusedIsNeverAcknowledged(t *testing.T) {
	admitter := newAssessmentAdmitter(t, &recordingAssessments{failure: errors.New("no leader for partition")})

	acknowledgement, err := admitter.Admit(context.Background(), identity(), "acme", fixtures.AssessmentBatch("assessment-1", posture()))
	if acknowledgement != nil || !errors.Is(err, ingest.ErrBackboneUnavailable) {
		t.Fatalf("an assessment the backbone did not take was answered %+v, %v", acknowledgement, err)
	}
}

func TestTheAssessmentAdmitterRefusesAnIncompletePolicy(t *testing.T) {
	instruments := ingest.NewAssessmentMetrics(metrics.New("test"))
	for name, policy := range map[string]ingest.AssessmentPolicy{
		"no gateway":         {MaxAssessmentsPerBatch: 1},
		"no ceiling":         {Gateway: "gateway-a"},
		"above the contract": {Gateway: "gateway-a", MaxAssessmentsPerBatch: assessment.MaxAssessmentsPerBatch + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ingest.NewAssessmentAdmitter(&recordingAssessments{}, policy, instruments); err == nil {
				t.Fatal("expected the admitter to refuse the policy")
			}
		})
	}
}

func TestAnAssessmentHeavierThanTheBackboneCarriesIsRefusedForGood(t *testing.T) {
	backbone := &recordingAssessments{}
	admitter := newAssessmentAdmitter(t, backbone)

	heavy := fixtures.Posture{AssessmentID: "asm-0000000002", At: admissionClock.Add(-time.Minute)}.Assessment()
	if !fixtures.Bloat(heavy, assessment.MaxAssessmentBytes+4<<10) {
		t.Fatal("no assessment weighs that much")
	}
	_, err := admitter.Admit(context.Background(), identity(), "acme", fixtures.AssessmentBatch("assessment-1", posture(), heavy))

	rejection := rejectionOf(t, err)
	if rejection.Code != ingest.CodeInvalidAssessment || rejection.EventIndex != 1 || rejection.Field != "assessment" {
		t.Fatalf("an assessment above the ceiling was refused as %+v, and an agent sends again whatever is not refused by its index", rejection)
	}
	if len(backbone.published) != 0 {
		t.Fatal("a batch holding an assessment the backbone cannot carry reached the backbone")
	}
}
