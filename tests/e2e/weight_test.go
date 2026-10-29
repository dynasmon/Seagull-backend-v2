package e2e_test

import (
	"fmt"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

// Every batch the gateway admits carries its records in field 3, so a body of
// nothing but that field, empty, is the most a body of its length can hold.
func emptiest(size int) []byte {
	body := make([]byte, 0, size)
	for len(body)+2 <= size {
		body = append(body, 0x1a, 0x00)
	}
	return body
}

func thousand(batchID string) *ingestv1.EventBatch {
	at := time.Now().UTC()
	events := make([]*eventv1.Event, 0, 1000)
	for index := range 1000 {
		events = append(events, fixtures.SSHAuthentication{
			EventID: fmt.Sprintf("%s-%06d", batchID, index), At: at, Sequence: uint64(index),
		}.Event())
	}
	return fixtures.Batch(batchID, events...)
}

func TestABodyThatWouldCostMoreToDecodeThanTheGatewayHoldsIsRefusedUndecoded(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	for _, url := range []string{gateway.url(), gateway.inventoryURL(), gateway.statusURL(), gateway.assessmentsURL()} {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		response, payload := gateway.postTo(t, client, url, ingest.ContentType, emptiest(1<<20))
		runtime.ReadMemStats(&after)

		if response.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("%s answered a body of a million empty records with %d: %s", url, response.StatusCode, payload)
			continue
		}
		if code := decodeRejection(t, payload).GetCode(); code != string(ingest.CodeBatchTooLarge) {
			t.Errorf("%s refused it as %q, which an agent does not read as a batch to split", url, code)
		}
		if spent := after.TotalAlloc - before.TotalAlloc; spent > 32<<20 {
			t.Errorf("%s allocated %d bytes refusing a body of 1 MiB, so it was decoded before it was weighed", url, spent)
		}
	}
}

func TestABatchWeighedAboveTheRoomLeftIsAskedToComeBack(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	gateway := startGateway(t, gatewayOptions{
		backbone:          &backbone{release: release, entered: entered},
		maxEventsPerBatch: 1000,
		maxInflightBytes:  3 << 20,
	})
	holding := gateway.client(t, "web-01")
	waiting := gateway.client(t, "web-02")

	held := make(chan int, 1)
	go func() {
		response, _ := gateway.send(t, holding, thousand("batch-held"))
		held <- response.StatusCode
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first batch never reached the backbone")
	}

	refused := thousand("batch-refused")
	response, payload := gateway.send(t, waiting, refused)
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a batch whose decoding the gateway had no room for answered %d: %s", response.StatusCode, payload)
	}
	if code := decodeRejection(t, payload).GetCode(); code != ingest.CodeAtCapacity {
		t.Errorf("the refusal reads %q: the batch was taken into room the gateway did not have", code)
	}
	if retry := response.Header.Get("Retry-After"); retry == "" {
		t.Error("the refusal does not tell the agent when to come back")
	}

	close(release)
	if status := <-held; status != http.StatusOK {
		t.Fatalf("the batch that was already in flight answered %d", status)
	}
	if again, payload := gateway.send(t, waiting, refused); again.StatusCode != http.StatusOK {
		t.Fatalf("the same batch, sent again once there was room, answered %d: %s", again.StatusCode, payload)
	}
}
