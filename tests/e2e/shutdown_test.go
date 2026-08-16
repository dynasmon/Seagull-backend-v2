package e2e_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-v2/tests/fixtures"
)

func TestShutdownWaitsForABatchAlreadyInFlight(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	gateway := startGateway(t, gatewayOptions{
		backbone: &backbone{release: release, entered: entered},
	})
	client := gateway.client(t, "web-01")

	type result struct {
		status int
		body   []byte
	}
	answered := make(chan result, 1)
	go func() {
		response, payload := gateway.send(t, client, fixtures.Batch("batch-drain", fixtures.SSHAuthentication{}.Event()))
		answered <- result{status: response.StatusCode, body: payload}
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the batch never reached the backbone")
	}

	gateway.stop()

	select {
	case <-answered:
		t.Fatal("shutdown abandoned a batch that was still being made durable")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	select {
	case answer := <-answered:
		if answer.status != http.StatusOK {
			t.Fatalf("the in-flight batch was not completed: %d", answer.status)
		}
		if acknowledgement := decodeAck(t, answer.body); !acknowledgement.GetDurable() {
			t.Fatal("the in-flight batch was not acknowledged as durable")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight batch was never answered")
	}

	gateway.awaitStop(t, 5*time.Second)
}
