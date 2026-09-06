package e2e_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
)

func TestAgentBatchTravelsFromMutualTLSToTheBackbone(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	batch := fixtures.Batch("batch-0001",
		fixtures.SSHAuthentication{EventID: "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", Username: "root"}.Event(),
		fixtures.SSHAuthentication{EventID: "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb", Username: "admin"}.Event(),
	)

	response, payload := gateway.send(t, client, batch)

	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.StatusCode, payload)
	}
	acknowledgement := decodeAck(t, payload)
	if !acknowledgement.GetAccepted() || !acknowledgement.GetDurable() || acknowledgement.GetReceived() != 2 {
		t.Fatalf("the agent cannot commit on this acknowledgement: %+v", acknowledgement)
	}
	if len(gateway.backbone.published) != 2 {
		t.Fatalf("expected 2 events on the backbone, got %d", len(gateway.backbone.published))
	}

	published := gateway.backbone.published[0]
	if published.GetOrigin().GetAgentId() != "web-01" {
		t.Fatalf("the certificate identity did not reach the event: %q", published.GetOrigin().GetAgentId())
	}
	if published.GetOrigin().GetTenantId() != "acme" {
		t.Fatalf("the tenant was not stamped: %q", published.GetOrigin().GetTenantId())
	}
	if published.GetReception().GetBatchId() != "batch-0001" {
		t.Fatalf("the batch was not recorded on the event: %+v", published.GetReception())
	}
	if published.GetReception().GetIngestTime() == nil {
		t.Fatal("the platform did not stamp an ingest time")
	}
}

func TestCertificateIdentityOverridesTheClaimedAgent(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	impersonating := fixtures.SSHAuthentication{AgentID: "domain-controller"}.Event()
	response, payload := gateway.send(t, client, fixtures.Batch("batch-0002", impersonating))

	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.StatusCode, payload)
	}
	if got := gateway.backbone.published[0].GetOrigin().GetAgentId(); got != "web-01" {
		t.Fatalf("an agent chose its own identity: %q", got)
	}
}

func TestConnectionWithoutAClientCertificateIsRefused(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})

	request, err := http.NewRequest(http.MethodPost, gateway.url(), bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	_, err = gateway.anonymousClient(t).Do(request)

	if err == nil {
		t.Fatal("an anonymous client reached the ingest endpoint")
	}
}

func TestCertificateFromAnotherAuthorityIsRefused(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})

	foreign, err := devpki.NewAuthority("Someone Else CA", time.Hour)
	if err != nil {
		t.Fatalf("create foreign authority: %v", err)
	}
	forged, err := foreign.IssueClient("web-01", time.Hour)
	if err != nil {
		t.Fatalf("issue foreign certificate: %v", err)
	}

	client := gateway.clientWith(t, forged, gateway.authority.Material().CertificatePEM)
	request, err := http.NewRequest(http.MethodPost, gateway.url(), bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	if _, err := client.Do(request); err == nil {
		t.Fatal("a certificate from an unknown authority was accepted")
	} else if !isHandshakeFailure(err) && !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected the handshake to fail, got %v", err)
	}
}

func TestBatchLargerThanTheBodyCeilingIsRefused(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{maxBodyBytes: 4096})
	client := gateway.client(t, "web-01")

	batch := fixtures.Batch("batch-0003")
	for index := range 100 {
		batch.Events = append(batch.Events, fixtures.SSHAuthentication{
			EventID: paddedID(index),
		}.Event())
	}

	response, _ := gateway.send(t, client, batch)

	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", response.StatusCode)
	}
	if len(gateway.backbone.published) != 0 {
		t.Fatal("an oversized body reached the backbone")
	}
}

func TestNonProtobufContentTypeIsRefused(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	response, _ := gateway.post(t, client, "application/json", []byte(`{"events":[]}`))

	if response.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", response.StatusCode)
	}
}

func TestMalformedProtobufIsRefused(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	response, payload := gateway.post(t, client, ingest.ContentType, []byte{0xff, 0xff, 0xff, 0xff})

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
	if code := decodeRejection(t, payload).GetCode(); code != "malformed_payload" {
		t.Fatalf("unexpected rejection code %q", code)
	}
}

func TestInvalidEventIsRefusedWithItsPosition(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	broken := fixtures.SSHAuthentication{EventID: "cccccccc-3333-4333-8333-cccccccccccc"}.Event()
	broken.GetAuthentication().Network.Source.Ip = "not-an-address"
	batch := fixtures.Batch("batch-0004", fixtures.SSHAuthentication{}.Event(), broken)

	response, payload := gateway.send(t, client, batch)

	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", response.StatusCode)
	}
	rejection := decodeRejection(t, payload)
	if rejection.GetEventIndex() != 1 || rejection.GetField() != "authentication.network.source.ip" {
		t.Fatalf("the rejection does not locate the problem: %+v", rejection)
	}
	if len(gateway.backbone.published) != 0 {
		t.Fatal("a batch holding an invalid event reached the backbone")
	}
}

func TestUnsupportedProtocolVersionAnswersUpgradeRequired(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	batch := fixtures.Batch("batch-0005", fixtures.SSHAuthentication{}.Event())
	batch.ProtocolVersion = 42

	response, payload := gateway.send(t, client, batch)

	if response.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("expected 426, got %d", response.StatusCode)
	}
	if code := decodeRejection(t, payload).GetCode(); code != string(ingest.CodeUnsupportedProtocol) {
		t.Fatalf("unexpected rejection code %q", code)
	}
}

func TestAnUnavailableBackboneNeverAcknowledges(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{
		backbone: &backbone{failure: errors.New("all brokers down")},
	})
	client := gateway.client(t, "web-01")

	response, payload := gateway.send(t, client, fixtures.Batch("batch-0006", fixtures.SSHAuthentication{}.Event()))

	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", response.StatusCode)
	}
	if response.Header.Get("Retry-After") == "" {
		t.Fatal("a retryable refusal must tell the agent when to come back")
	}
	if acknowledgement := decodeAck(t, payload); acknowledgement.GetDurable() {
		t.Fatal("a batch that never reached the backbone was acknowledged as durable")
	}
}

func TestBackboneFailureDetailStaysOffTheWire(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{
		backbone: &backbone{failure: errors.New("dial redpanda-1.internal:9092: connection refused")},
	})
	client := gateway.client(t, "web-01")

	_, payload := gateway.send(t, client, fixtures.Batch("batch-0007", fixtures.SSHAuthentication{}.Event()))

	if strings.Contains(string(payload), "redpanda-1.internal") {
		t.Fatalf("the refusal described the platform's internals: %s", payload)
	}
}

func TestAgentPastItsRateBudgetIsRefused(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{ratePerSecond: 1, rateBurst: 2})
	client := gateway.client(t, "web-01")

	var lastStatus int
	for attempt := range 5 {
		response, _ := gateway.send(t, client, fixtures.Batch(fmt.Sprintf("batch-rate-%d", attempt), fixtures.SSHAuthentication{}.Event()))
		lastStatus = response.StatusCode
	}

	if lastStatus != http.StatusTooManyRequests {
		t.Fatalf("expected the agent to be throttled, got %d", lastStatus)
	}
}

func TestBatchAboveTheEventCeilingIsRefused(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{maxEventsPerBatch: 2, maxBodyBytes: 1 << 20})
	client := gateway.client(t, "web-01")

	batch := fixtures.Batch("batch-0008")
	for index := range 3 {
		batch.Events = append(batch.Events, fixtures.SSHAuthentication{EventID: paddedID(index)}.Event())
	}

	response, payload := gateway.send(t, client, batch)

	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", response.StatusCode)
	}
	if code := decodeRejection(t, payload).GetCode(); code != string(ingest.CodeBatchTooLarge) {
		t.Fatalf("unexpected rejection code %q", code)
	}
}

func paddedID(index int) string {
	return fmt.Sprintf("eeeeeeee-0000-4000-8000-%012d", index)
}

func TestOneProcessExposesEveryListenerOnOneOperationalSurface(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	if _, payload := gateway.send(t, client, fixtures.Batch("batch-metrics", fixtures.SSHAuthentication{}.Event())); len(payload) == 0 {
		t.Fatal("the gateway answered nothing")
	}

	operational := &http.Client{Timeout: 10 * time.Second}
	t.Cleanup(operational.CloseIdleConnections)

	response, err := operational.Get("http://" + gateway.opsAddress + "/metrics")
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	for _, expected := range []string{
		`route="ingest_events"`,
		`seagull_ingest_batches_total{outcome="accepted"}`,
		`seagull_ingest_event_lag_seconds_bucket`,
	} {
		if !strings.Contains(string(body), expected) {
			t.Fatalf("%s missing from the exposition", expected)
		}
	}
}

// A body ceiling bounds one caller and nothing about it bounds the sum of them.
// A gateway holding as much as it was bounded to refuses the next batch rather
// than accepting work it has no memory for.
func TestAGatewayAtItsCeilingRefusesWorkInsteadOfHoldingIt(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	gateway := startGateway(t, gatewayOptions{
		backbone:            &backbone{release: release, entered: entered},
		maxInflightRequests: 1,
	})

	holding := gateway.client(t, "web-01")
	waiting := gateway.client(t, "web-02")

	held := make(chan int, 1)
	go func() {
		response, _ := gateway.send(t, holding, fixtures.Batch("batch-held",
			fixtures.SSHAuthentication{EventID: "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"}.Event()))
		held <- response.StatusCode
	}()

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first batch never reached the backbone")
	}

	response, payload := gateway.send(t, waiting, fixtures.Batch("batch-refused",
		fixtures.SSHAuthentication{EventID: "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"}.Event()))
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a gateway at its ceiling answered %d: %s", response.StatusCode, payload)
	}
	if code := decodeRejection(t, payload).GetCode(); code != ingest.CodeAtCapacity {
		t.Errorf("the refusal reads %q, so an agent cannot tell it from a rejected batch", code)
	}
	if retry := response.Header.Get("Retry-After"); retry == "" {
		t.Error("the refusal does not tell the agent when to come back")
	}

	close(release)
	if status := <-held; status != http.StatusOK {
		t.Fatalf("the batch that was already in flight answered %d", status)
	}

	admitted, _ := gateway.send(t, waiting, fixtures.Batch("batch-after",
		fixtures.SSHAuthentication{EventID: "cccccccc-3333-4333-8333-cccccccccccc"}.Event()))
	if admitted.StatusCode != http.StatusOK {
		t.Fatalf("the gateway kept refusing after the work it was holding finished: %d", admitted.StatusCode)
	}
}
