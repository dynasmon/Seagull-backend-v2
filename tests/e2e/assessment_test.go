package e2e_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func TestAnAssessmentTravelsFromMutualTLSToTheBackboneAsTheAgentTheCertificateNames(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	assessed := fixtures.Posture{AgentID: "domain-controller", Revision: 9}.Assessment()
	response, payload := gateway.sendAssessments(t, client, fixtures.AssessmentBatch("assessment-0001", assessed))

	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.StatusCode, payload)
	}
	if acknowledgement := decodeAck(t, payload); !acknowledgement.GetAccepted() || !acknowledgement.GetDurable() || acknowledgement.GetReceived() != 1 {
		t.Fatalf("the agent cannot let go of its assessment on this acknowledgement: %+v", acknowledgement)
	}
	if len(gateway.backbone.assessed) != 1 || len(gateway.backbone.status) != 0 || len(gateway.backbone.published) != 0 || len(gateway.backbone.inventory) != 0 {
		t.Fatalf("the assessment landed on %d assessment, %d status, %d event and %d inventory records",
			len(gateway.backbone.assessed), len(gateway.backbone.status), len(gateway.backbone.published), len(gateway.backbone.inventory))
	}
	published := gateway.backbone.assessed[0]
	if published.GetOrigin().GetAgentId() != "web-01" || published.GetOrigin().GetTenantId() != "acme" {
		t.Fatalf("the assessment speaks for %q in %q", published.GetOrigin().GetAgentId(), published.GetOrigin().GetTenantId())
	}
	if reception := published.GetReception(); reception.GetBatchId() != "assessment-0001" || reception.GetGateway() != "gateway-test" ||
		time.Since(reception.GetIngestTime().AsTime()) > time.Minute {
		t.Fatalf("the assessment was received as %+v", reception)
	}
	if published.GetPolicyRevision() != 9 || len(published.GetResults()) != 3 || published.GetResults()[0].GetOutcome() != assessmentv1.Outcome_OUTCOME_FAIL {
		t.Fatalf("the assessment changed on the way: %+v", published)
	}
}

// One gate stands in front of every kind of record, so an agent the platform
// stopped admitting cannot file a posture either.
func TestTheAssessmentRouteRefusesAnAgentTheRegistryDoesNotAdmit(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})

	unregistered := gateway.unregistered(t, "web-99")
	response, payload := gateway.sendAssessments(t, unregistered, fixtures.AssessmentBatch("assessment-0002", fixtures.Posture{}.Assessment()))
	if response.StatusCode != http.StatusForbidden || decodeRejection(t, payload).GetCode() != ingest.CodeNotRegistered {
		t.Fatalf("an unregistered agent was answered %d: %s", response.StatusCode, payload)
	}

	revoked := gateway.client(t, "web-03")
	if err := gateway.roster.Apply(&agentv1.Admission{AgentId: "web-03", TenantId: "acme", State: agent.Revoked.Wire(), Revision: 2}); err != nil {
		t.Fatalf("revoke web-03: %v", err)
	}
	response, payload = gateway.sendAssessments(t, revoked, fixtures.AssessmentBatch("assessment-0003", fixtures.Posture{}.Assessment()))
	if response.StatusCode != http.StatusForbidden || decodeRejection(t, payload).GetCode() != ingest.CodeNotAdmitted {
		t.Fatalf("a revoked agent was answered %d: %s", response.StatusCode, payload)
	}
	if len(gateway.backbone.assessed) != 0 {
		t.Fatal("an assessment from an agent the platform does not admit reached the backbone")
	}
}

func TestAnAssessmentTheContractRefusesIsAnsweredWithItsPositionAndField(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	broken := fixtures.Posture{AssessmentID: "asm-0000000002"}.Assessment()
	broken.Results[1].CheckId = broken.Results[0].GetCheckId()
	response, payload := gateway.sendAssessments(t, client, fixtures.AssessmentBatch("assessment-0004", fixtures.Posture{}.Assessment(), broken))
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unexpected status %d: %s", response.StatusCode, payload)
	}
	rejection := decodeRejection(t, payload)
	if rejection.GetCode() != string(ingest.CodeInvalidAssessment) || rejection.GetEventIndex() != 1 || rejection.GetField() != "results[1].check_id" {
		t.Fatalf("the refusal says %+v", rejection)
	}

	response, payload = gateway.postTo(t, client, gateway.assessmentsURL(), ingest.ContentType, []byte{0xff, 0xff, 0xff, 0xff})
	if response.StatusCode != http.StatusBadRequest || decodeRejection(t, payload).GetCode() != string(ingest.CodeMalformedPayload) {
		t.Fatalf("a payload that does not decode was answered %d: %s", response.StatusCode, payload)
	}
	if len(gateway.backbone.assessed) != 0 {
		t.Fatal("a refused batch reached the backbone")
	}
}
