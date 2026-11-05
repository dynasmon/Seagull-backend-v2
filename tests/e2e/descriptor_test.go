package e2e_test

import (
	"io"
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

func describedAt(t *testing.T, client *http.Client, url, tag string) (*http.Response, []byte, error) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	if tag != "" {
		request.Header.Set("If-None-Match", tag)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	return response, body, nil
}

func decodeDescriptor(t *testing.T, response *http.Response, body []byte) *platformv1.Descriptor {
	t.Helper()
	var described platformv1.Descriptor
	if err := proto.Unmarshal(body, &described); err != nil || response.StatusCode != http.StatusOK || response.Header.Get("ETag") == "" {
		t.Fatalf("the descriptor was answered %d with the tag %q (%v): %s", response.StatusCode, response.Header.Get("ETag"), err, body)
	}
	return &described
}

func TestAnAgentLearnsWhatTheGatewayAdmitsBeforeItSendsAnything(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{maxBodyBytes: 3 << 20, maxEventsPerBatch: 77, maxRecordsPerBatch: 12, maxReportsPerBatch: 5, maxAssessments: 4})
	url := "https://" + gateway.address + ingest.DescriptorPath

	response, body, err := describedAt(t, gateway.client(t, "web-01"), url, "")
	if err != nil {
		t.Fatalf("ask for the descriptor: %v", err)
	}
	described := decodeDescriptor(t, response, body)
	admits := map[string]uint32{ingest.EventsRoute: 77, ingest.InventoryRoute: 12, ingest.StatusRoute: 5, ingest.AssessmentsRoute: 4}
	for _, stream := range described.GetStreams() {
		if records, known := admits[stream.GetRoute()]; !known || stream.GetMaxRecordsPerBatch() != records {
			t.Errorf("the gateway describes %s with %d records a batch", stream.GetRoute(), stream.GetMaxRecordsPerBatch())
		}
		delete(admits, stream.GetRoute())
	}
	if len(admits) != 0 || described.GetMaxBodyBytes() != 3<<20 || described.GetProtocolVersion() != protocol.Version {
		t.Fatalf("the gateway left %v undescribed and describes a body of %d", admits, described.GetMaxBodyBytes())
	}

	tag := response.Header.Get("ETag")
	if unchanged, body, err := describedAt(t, gateway.client(t, "web-01"), url, tag); err != nil || unchanged.StatusCode != http.StatusNotModified || len(body) != 0 {
		t.Fatalf("asked again with its tag, the descriptor was answered %v with %d bytes (%v)", unchanged, len(body), err)
	}

	refused, body, err := describedAt(t, gateway.unregistered(t, "web-02"), url, "")
	if err != nil || refused.StatusCode != http.StatusForbidden || decodeRejection(t, body).GetCode() != ingest.CodeNotRegistered {
		t.Fatalf("an agent the registry never named was answered %v (%v)", refused, err)
	}
	if _, _, err := describedAt(t, gateway.anonymousClient(t), url, ""); err == nil {
		t.Fatal("a caller without a certificate reached the descriptor")
	}
}

func TestAnAgentLearnsWhatTheControlPlaneOffersItBeforeAskingForAnything(t *testing.T) {
	plane := startControlAPI(t, nil)
	operator := plane.caller(t, "e2e-admin")
	token := plane.open(t, operator).GetToken()
	plane.register(t, operator, token, "e2e-agent-90")
	key, requestPEM := keyAndRequest(t, "e2e-agent-90")
	agent := plane.agentClient(t, key, plane.issue(t, operator, token, "e2e-agent-90", requestPEM))

	response, body, err := describedAt(t, agent, "https://"+plane.renewalAddress+control.DescriptorPath, "")
	if err != nil {
		t.Fatalf("ask for the descriptor: %v", err)
	}
	offered := map[string]string{}
	for _, capability := range decodeDescriptor(t, response, body).GetCapabilities() {
		offered[capability.GetName()] = capability.GetRoute()
	}
	want := map[string]string{
		protocol.CapabilityRenewal: http.MethodPost + " " + control.RenewalPath,
		protocol.CapabilityPolicy:  http.MethodGet + " " + control.PolicyPath,
		protocol.CapabilityUpdate:  http.MethodGet + " " + control.UpdatePath,
	}
	if len(offered) != len(want) {
		t.Fatalf("a plane that renews, hands policies and updates offers %v", offered)
	}
	for name, route := range want {
		if offered[name] != route {
			t.Errorf("%s is offered at %q, and it is served at %q", name, offered[name], route)
		}
	}

	if _, _, err := describedAt(t, operator, "https://"+plane.renewalAddress+control.DescriptorPath, ""); err == nil {
		t.Fatal("an operator certificate reached the agent listener's descriptor")
	}
}
