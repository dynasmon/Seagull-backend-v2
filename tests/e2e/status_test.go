package e2e_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func TestAStatusReportTravelsFromMutualTLSToTheBackboneAsTheAgentTheCertificateNames(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	report := fixtures.Report{AgentID: "domain-controller", Sequence: 9, Condition: agentv1.Status_CONDITION_DEGRADED}.Status()
	response, payload := gateway.sendStatus(t, client, fixtures.StatusBatch("status-0001", report))

	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.StatusCode, payload)
	}
	if acknowledgement := decodeAck(t, payload); !acknowledgement.GetAccepted() || !acknowledgement.GetDurable() || acknowledgement.GetReceived() != 1 {
		t.Fatalf("the agent cannot let go of its report on this acknowledgement: %+v", acknowledgement)
	}
	if len(gateway.backbone.status) != 1 || len(gateway.backbone.published) != 0 || len(gateway.backbone.inventory) != 0 {
		t.Fatalf("the report landed on %d status, %d event and %d inventory records",
			len(gateway.backbone.status), len(gateway.backbone.published), len(gateway.backbone.inventory))
	}
	published := gateway.backbone.status[0]
	if published.GetOrigin().GetAgentId() != "web-01" || published.GetOrigin().GetTenantId() != "acme" {
		t.Fatalf("the report speaks for %q in %q", published.GetOrigin().GetAgentId(), published.GetOrigin().GetTenantId())
	}
	if reception := published.GetReception(); reception.GetBatchId() != "status-0001" || reception.GetGateway() != "gateway-test" ||
		time.Since(reception.GetIngestTime().AsTime()) > time.Minute {
		t.Fatalf("the report was received as %+v", reception)
	}
	if published.GetSequence() != 9 || published.GetCondition() != agentv1.Status_CONDITION_DEGRADED {
		t.Fatalf("the report changed on the way: %+v", published)
	}
}

// One gate stands in front of every kind of record, so an agent the platform
// stopped admitting is not heard from on this route either.
func TestTheStatusRouteRefusesAnAgentTheRegistryDoesNotAdmit(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})

	unregistered := gateway.unregistered(t, "web-99")
	response, payload := gateway.sendStatus(t, unregistered, fixtures.StatusBatch("status-0002", fixtures.Report{}.Status()))
	if response.StatusCode != http.StatusForbidden || decodeRejection(t, payload).GetCode() != ingest.CodeNotRegistered {
		t.Fatalf("an unregistered agent was answered %d: %s", response.StatusCode, payload)
	}

	revoked := gateway.client(t, "web-03")
	if err := gateway.roster.Apply(&agentv1.Admission{AgentId: "web-03", TenantId: "acme", State: agent.Revoked.Wire(), Revision: 2}); err != nil {
		t.Fatalf("revoke web-03: %v", err)
	}
	response, payload = gateway.sendStatus(t, revoked, fixtures.StatusBatch("status-0003", fixtures.Report{}.Status()))
	if response.StatusCode != http.StatusForbidden || decodeRejection(t, payload).GetCode() != ingest.CodeNotAdmitted {
		t.Fatalf("a revoked agent was answered %d: %s", response.StatusCode, payload)
	}
	if len(gateway.backbone.status) != 0 {
		t.Fatal("a report from an agent the platform does not admit reached the backbone")
	}
}

func TestAStatusReportTheContractRefusesIsAnsweredWithItsPositionAndField(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	broken := fixtures.Report{}.Status()
	broken.Spool = nil
	response, payload := gateway.sendStatus(t, client, fixtures.StatusBatch("status-0004", fixtures.Report{}.Status(), broken))
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unexpected status %d: %s", response.StatusCode, payload)
	}
	rejection := decodeRejection(t, payload)
	if rejection.GetCode() != string(ingest.CodeInvalidReport) || rejection.GetEventIndex() != 1 || rejection.GetField() != "spool" {
		t.Fatalf("the refusal says %+v", rejection)
	}

	response, payload = gateway.postTo(t, client, gateway.statusURL(), ingest.ContentType, []byte{0xff, 0xff, 0xff, 0xff})
	if response.StatusCode != http.StatusBadRequest || decodeRejection(t, payload).GetCode() != string(ingest.CodeMalformedPayload) {
		t.Fatalf("a payload that does not decode was answered %d: %s", response.StatusCode, payload)
	}
	if len(gateway.backbone.status) != 0 {
		t.Fatal("a refused batch reached the backbone")
	}
}
