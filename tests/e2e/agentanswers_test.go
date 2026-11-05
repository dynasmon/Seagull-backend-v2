package e2e_test

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

type stale struct{}

func (stale) Stale() bool { return true }

func acknowledged(status int) proto.Message {
	if status == http.StatusOK {
		return &ingestv1.BatchAck{}
	}
	return &ingestv1.Rejection{}
}

func described(status int) proto.Message {
	if status == http.StatusOK {
		return &platformv1.Descriptor{}
	}
	return &ingestv1.Rejection{}
}

func controlled(answered proto.Message) func(int) proto.Message {
	return func(status int) proto.Message {
		if status >= 200 && status < 300 {
			return answered
		}
		return &controlv1.Refusal{}
	}
}

// Every answer an agent reads from a platform of this commit, recorded from the
// real listeners: each stream's acknowledgement and every refusal it can give,
// both descriptors, and what the agent listener answers about certificates,
// policies and updates. The agent consumes the recording; this repository holds
// every answer to it, so one that changes fails until it is recorded again.
func TestTheAnswersAnAgentReadsAreTheOnesRecorded(t *testing.T) {
	book := newAnswerBook(t)
	streamAnswers(t, book)
	boundedStreamAnswers(t, book)
	agentListenerAnswers(t, book)
	book.settle(t)
}

func streamAnswers(t *testing.T, book *answerBook) {
	held := &backbone{}
	gateway := startGateway(t, gatewayOptions{maxBodyBytes: 64 << 10, maxEventsPerBatch: 4, maxRecordsPerBatch: 2,
		maxReportsPerBatch: 2, maxAssessments: 2, backbone: held})
	admitted := gateway.client(t, "web-01")
	revoked := gateway.client(t, "web-03")
	if err := gateway.roster.Apply(&agentv1.Admission{AgentId: "web-03", TenantId: "acme", State: agent.Revoked.Wire(), Revision: 2}); err != nil {
		t.Fatal(err)
	}
	unregistered := gateway.unregistered(t, "web-02")

	now := time.Now().UTC()
	event := func(id string, at time.Time) *eventv1.Event {
		return fixtures.SSHAuthentication{EventID: id, At: at}.Event()
	}
	accepted := fixtures.Batch("batch-accepted", event("e0000000-0000-4000-8000-000000000001", now.Add(-time.Minute)))
	versioned := func(protocol uint32) *ingestv1.EventBatch {
		batch := fixtures.Batch("batch-protocol", event("e0000000-0000-4000-8000-000000000002", now.Add(-time.Minute)))
		batch.ProtocolVersion = protocol
		return batch
	}
	second := func(changed func(*eventv1.Event)) *ingestv1.EventBatch {
		refused := event("e0000000-0000-4000-8000-000000000004", now.Add(-time.Minute))
		changed(refused)
		return fixtures.Batch("batch-second", event("e0000000-0000-4000-8000-000000000003", now.Add(-time.Minute)), refused)
	}
	var many []*eventv1.Event
	for index := range 5 {
		many = append(many, event("e0000000-0000-4000-8000-00000000010"+string(rune('0'+index)), now.Add(-time.Minute)))
	}
	malformedID := fixtures.Batch("not a batch id", event("e0000000-0000-4000-8000-000000000005", now.Add(-time.Minute)))

	events := func(name string, client *http.Client, body []byte, contentType string) {
		book.ask(t, asking{name: name, listener: "gateway", client: client, method: http.MethodPost, url: gateway.url(),
			body: body, contentType: contentType, reply: acknowledged})
	}
	events("events-accepted", admitted, encoded(t, accepted), ingest.ContentType)
	events("events-replayed", admitted, encoded(t, accepted), ingest.ContentType)
	events("events-protocol-2", admitted, encoded(t, versioned(2)), ingest.ContentType)
	events("events-schema-2", admitted, encoded(t, second(func(e *eventv1.Event) { e.SchemaVersion = 2 })), ingest.ContentType)
	events("events-unknown-class", admitted, encoded(t, second(func(e *eventv1.Event) { e.EventClass = eventv1.EventClass(99) })), ingest.ContentType)
	events("events-too-old", admitted, encoded(t, second(func(e *eventv1.Event) {
		e.Time = fixtures.SSHAuthentication{At: now.Add(-8 * 24 * time.Hour)}.Event().GetTime()
	})), ingest.ContentType)
	events("events-ahead", admitted, encoded(t, second(func(e *eventv1.Event) {
		e.Time = fixtures.SSHAuthentication{At: now.Add(time.Hour)}.Event().GetTime()
	})), ingest.ContentType)
	events("events-too-many", admitted, encoded(t, fixtures.Batch("batch-too-many", many...)), ingest.ContentType)
	events("events-malformed-batch-id", admitted, encoded(t, malformedID), ingest.ContentType)
	events("events-malformed-payload", admitted, []byte("this is not a batch"), ingest.ContentType)
	events("events-unsupported-media-type", admitted, encoded(t, accepted), "application/json")
	events("events-body-too-large", admitted, bytes.Repeat([]byte{0x0a, 0x00}, 40<<10), ingest.ContentType)
	held.failure = errors.New("the backbone is away")
	events("events-backbone-unavailable", admitted, encoded(t, accepted), ingest.ContentType)
	held.failure = nil
	events("events-agent-not-registered", unregistered, encoded(t, accepted), ingest.ContentType)
	events("events-agent-not-admitted", revoked, encoded(t, accepted), ingest.ContentType)

	scan := fixtures.PackageScan{At: now.Add(-time.Minute)}.Record
	inventory := func(name string, client *http.Client, batch *inventoryv1.RecordBatch) {
		book.ask(t, asking{name: name, listener: "gateway", client: client, method: http.MethodPost, url: gateway.inventoryURL(),
			body: encoded(t, batch), contentType: ingest.ContentType, reply: acknowledged})
	}
	unknownKind := scan()
	unknownKind.Kind = inventoryv1.Kind(99)
	unknownMode := scan()
	unknownMode.Mode = inventoryv1.Mode(99)
	inventoryProtocol := fixtures.InventoryBatch("batch-inventory-protocol", scan())
	inventoryProtocol.ProtocolVersion = 2
	inventory("inventory-accepted", admitted, fixtures.InventoryBatch("batch-inventory", scan()))
	inventory("inventory-protocol-2", admitted, inventoryProtocol)
	inventory("inventory-unknown-kind", admitted, fixtures.InventoryBatch("batch-inventory-kind", scan(), unknownKind))
	inventory("inventory-unknown-mode", admitted, fixtures.InventoryBatch("batch-inventory-mode", scan(), unknownMode))
	inventory("inventory-agent-not-admitted", revoked, fixtures.InventoryBatch("batch-inventory", scan()))

	report := fixtures.Report{At: now.Add(-time.Minute)}.Status
	status := func(name string, batch *agentv1.StatusBatch) {
		book.ask(t, asking{name: name, listener: "gateway", client: admitted, method: http.MethodPost, url: gateway.statusURL(),
			body: encoded(t, batch), contentType: ingest.ContentType, reply: acknowledged})
	}
	newer := report()
	newer.SchemaVersion = 2
	status("status-accepted", fixtures.StatusBatch("batch-status", report()))
	status("status-schema-2", fixtures.StatusBatch("batch-status-schema", report(), newer))

	posture := fixtures.Posture{At: now.Add(-time.Minute)}.Assessment
	assessments := func(name string, batch *assessmentv1.AssessmentBatch) {
		book.ask(t, asking{name: name, listener: "gateway", client: admitted, method: http.MethodPost, url: gateway.assessmentsURL(),
			body: encoded(t, batch), contentType: ingest.ContentType, reply: acknowledged})
	}
	unread := posture()
	unread.SchemaVersion = 2
	assessments("assessments-accepted", fixtures.AssessmentBatch("batch-assessment", posture()))
	assessments("assessments-schema-2", fixtures.AssessmentBatch("batch-assessment-schema", posture(), unread))

	descriptor := "https://" + gateway.address + ingest.DescriptorPath
	first := book.ask(t, asking{name: "gateway-descriptor", listener: "gateway", client: admitted, method: http.MethodGet, url: descriptor, reply: described})
	book.ask(t, asking{name: "gateway-descriptor-unchanged", listener: "gateway", client: admitted, method: http.MethodGet, url: descriptor,
		tag: first.Header.Get("ETag"), reply: described})
	book.ask(t, asking{name: "gateway-descriptor-agent-not-registered", listener: "gateway", client: unregistered, method: http.MethodGet,
		url: descriptor, reply: described})
}

// The refusals a gateway gives only when it is bounded or held: a budget spent,
// a batch weighing more than it can hold, no room left, and a roster it cannot
// vouch for.
func boundedStreamAnswers(t *testing.T, book *answerBook) {
	accepted := encoded(t, fixtures.Batch("batch-bounded", fixtures.SSHAuthentication{EventID: "e0000000-0000-4000-8000-000000000201"}.Event()))
	post := func(name string, client *http.Client, url string, body []byte) *http.Response {
		return book.ask(t, asking{name: name, listener: "gateway", client: client, method: http.MethodPost, url: url,
			body: body, contentType: ingest.ContentType, reply: acknowledged})
	}

	limited := startGateway(t, gatewayOptions{ratePerSecond: 0.001, rateBurst: 1})
	spending := limited.client(t, "web-01")
	if response, _ := limited.send(t, spending, fixtures.Batch("batch-spent", fixtures.SSHAuthentication{}.Event())); response.StatusCode != http.StatusOK {
		t.Fatalf("the batch that spends the budget was answered %d", response.StatusCode)
	}
	post("events-rate-limited", spending, limited.url(), accepted)

	heavy := startGateway(t, gatewayOptions{maxBodyBytes: 1 << 20, maxInflightBytes: 1 << 20})
	post("events-batch-too-large", heavy.client(t, "web-01"), heavy.url(), bytes.Repeat([]byte{0x1a, 0x00}, 32<<10))

	release, entered := make(chan struct{}), make(chan struct{})
	full := startGateway(t, gatewayOptions{backbone: &backbone{release: release, entered: entered}, maxInflightRequests: 1})
	holding, refused := full.client(t, "web-01"), full.client(t, "web-02")
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = full.send(t, holding, fixtures.Batch("batch-held", fixtures.SSHAuthentication{EventID: "e0000000-0000-4000-8000-000000000202"}.Event()))
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the held batch never reached the backbone")
	}
	post("events-gateway-at-capacity", refused, full.url(), accepted)
	close(release)
	<-done

	stalled := startGateway(t, gatewayOptions{currency: stale{}})
	behind := stalled.client(t, "web-01")
	post("events-roster-stale", behind, stalled.url(), accepted)
	book.ask(t, asking{name: "gateway-descriptor-roster-stale", listener: "gateway", client: behind, method: http.MethodGet,
		url: "https://" + stalled.address + ingest.DescriptorPath, reply: described})
}

func agentListenerAnswers(t *testing.T, book *answerBook) {
	plane := startControlAPI(t, nil)
	operator := plane.caller(t, "e2e-admin")
	token := plane.open(t, operator).GetToken()
	for _, id := range []string{"e2e-agent-70", "e2e-agent-71", "e2e-agent-72"} {
		plane.register(t, operator, token, id)
	}
	issue := func(name, agentID string, requestPEM []byte) *http.Response {
		return book.ask(t, asking{name: name, listener: "operator", client: operator, method: http.MethodPost,
			url: "https://" + plane.address + "/v1/agents/" + agentID + "/certificate", bearer: token,
			body: encoded(t, &agentv1.CertificateRequest{CsrPem: requestPEM}), contentType: control.ContentType,
			reply: controlled(&agentv1.IssuedCertificate{})})
	}
	key, requestPEM := keyAndRequest(t, "e2e-agent-70")
	issued := book.ask(t, asking{name: "issuance-accepted", listener: "operator", client: operator, method: http.MethodPost,
		url: "https://" + plane.address + "/v1/agents/e2e-agent-70/certificate", bearer: token,
		body: encoded(t, &agentv1.CertificateRequest{CsrPem: requestPEM}), contentType: control.ContentType,
		reply: controlled(&agentv1.IssuedCertificate{})})
	if issued.StatusCode != http.StatusCreated {
		t.Fatalf("issuing a certificate was answered %d", issued.StatusCode)
	}
	_, otherRequest := keyAndRequest(t, "e2e-agent-79")
	issue("issuance-other-agent", "e2e-agent-71", otherRequest)
	_, strangerRequest := keyAndRequest(t, "e2e-agent-78")
	issue("issuance-unregistered", "e2e-agent-78", strangerRequest)

	var certified agentv1.IssuedCertificate
	if err := proto.Unmarshal(book.files["issuance-accepted.reply.pb"], &certified); err != nil {
		t.Fatal(err)
	}
	agentClient := plane.agentClient(t, key, &certified)
	listener := "https://" + plane.renewalAddress
	renew := func(name string, client *http.Client, requestPEM []byte) *http.Response {
		return book.ask(t, asking{name: name, listener: "agent", client: client, method: http.MethodPost, url: listener + control.RenewalPath,
			body: encoded(t, &agentv1.RenewalRequest{CsrPem: requestPEM}), contentType: control.ContentType,
			reply: controlled(&agentv1.IssuedCertificate{})})
	}
	_, renewing := keyAndRequest(t, "e2e-agent-70")
	renew("renewal-renewed", agentClient, renewing)
	renew("renewal-asked-again", agentClient, renewing)
	_, another := keyAndRequest(t, "e2e-agent-70")
	renew("renewal-superseded", agentClient, another)

	revokedKey, revokedRequest := keyAndRequest(t, "e2e-agent-71")
	revokedClient := plane.agentClient(t, revokedKey, plane.issue(t, operator, token, "e2e-agent-71", revokedRequest))
	if response, body := plane.send(t, operator, http.MethodPost, "/v1/agents/e2e-agent-71/transition", token,
		&agentv1.TransitionRequest{To: agent.Revoked.Wire(), Note: "recorded for the agent"}); response.StatusCode != http.StatusOK {
		t.Fatalf("revoking was answered %d: %s", response.StatusCode, body)
	}
	_, afterRevocation := keyAndRequest(t, "e2e-agent-71")
	renew("renewal-revoked", revokedClient, afterRevocation)

	freshKey, freshRequest := keyAndRequest(t, "e2e-agent-72")
	fresh := plane.agentClient(t, freshKey, plane.issue(t, operator, token, "e2e-agent-72", freshRequest))
	get := func(name string, client *http.Client, path, tag string, answered proto.Message) *http.Response {
		return book.ask(t, asking{name: name, listener: "agent", client: client, method: http.MethodGet, url: listener + path,
			tag: tag, reply: controlled(answered)})
	}
	get("policy-none", fresh, control.PolicyPath, "", &policyv1.SignedPolicy{})
	plane.publishPolicy(t, operator, token, 1, "e2e-agent-72")
	served := get("policy-served", fresh, control.PolicyPath, "", &policyv1.SignedPolicy{})
	get("policy-unchanged", fresh, control.PolicyPath, served.Header.Get("ETag"), &policyv1.SignedPolicy{})
	get("policy-not-admitted", revokedClient, control.PolicyPath, "", &policyv1.SignedPolicy{})

	offered := get("update-offered", fresh, control.UpdatePath, "", &updatev1.Offer{})
	get("update-unchanged", fresh, control.UpdatePath, offered.Header.Get("ETag"), &updatev1.Offer{})
	get("update-not-admitted", revokedClient, control.UpdatePath, "", &updatev1.Offer{})

	first := get("agent-descriptor", fresh, control.DescriptorPath, "", &platformv1.Descriptor{})
	get("agent-descriptor-unchanged", fresh, control.DescriptorPath, first.Header.Get("ETag"), &platformv1.Descriptor{})
}
