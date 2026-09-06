package ingest_test

import (
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

func bounded(t *testing.T, bytes int64, requests int) *ingest.Capacity {
	t.Helper()

	capacity, err := ingest.NewCapacity(bytes, requests)
	if err != nil {
		t.Fatalf("bound what the gateway holds at once: %v", err)
	}
	return capacity
}

// Eight mebibytes is a reasonable batch; a hundred of them at once is not a
// reasonable gateway. The ceiling that matters is across every caller in flight.
func TestWorkPastTheByteCeilingIsRefusedRatherThanQueued(t *testing.T) {
	capacity := bounded(t, 16<<20, 100)

	first, held := capacity.Hold(8 << 20)
	if !held {
		t.Fatal("the first batch was refused")
	}
	if _, held = capacity.Hold(8 << 20); !held {
		t.Fatal("the second batch was refused inside the ceiling")
	}
	if _, held = capacity.Hold(1); held {
		t.Fatal("the gateway took work past what it was bounded to")
	}

	first()
	if _, held = capacity.Hold(8 << 20); !held {
		t.Fatal("releasing a batch did not make room for the next one")
	}
}

func TestWorkPastTheRequestCeilingIsRefusedEvenWhenItIsSmall(t *testing.T) {
	capacity := bounded(t, 1<<30, 2)

	if _, held := capacity.Hold(1); !held {
		t.Fatal("the first request was refused")
	}
	if _, held := capacity.Hold(1); !held {
		t.Fatal("the second request was refused inside the ceiling")
	}
	if _, held := capacity.Hold(1); held {
		t.Fatal("a third request was taken past the ceiling")
	}
}

func TestReleasingTwiceGivesBackWhatWasHeldOnce(t *testing.T) {
	capacity := bounded(t, 1<<20, 4)

	release, held := capacity.Hold(1 << 19)
	if !held {
		t.Fatal("the request was refused")
	}
	release()
	release()

	if bytes, requests := capacity.Held(); bytes != 0 || requests != 0 {
		t.Fatalf("the gateway holds %d bytes over %d requests after everything was released", bytes, requests)
	}
}

func TestNothingIsHeldAfterEveryCallerHasFinished(t *testing.T) {
	capacity := bounded(t, 1<<20, 64)

	var callers sync.WaitGroup
	for range 200 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if release, held := capacity.Hold(1 << 14); held {
				release()
			}
		}()
	}
	callers.Wait()

	if bytes, requests := capacity.Held(); bytes != 0 || requests != 0 {
		t.Fatalf("the gateway holds %d bytes over %d requests with nobody in flight", bytes, requests)
	}
}

func TestAGatewayThatHoldsNothingIsRefused(t *testing.T) {
	if _, err := ingest.NewCapacity(0, 10); err == nil {
		t.Error("a gateway bounded to no bytes was built")
	}
	if _, err := ingest.NewCapacity(1<<20, 0); err == nil {
		t.Error("a gateway bounded to no requests was built")
	}
}

// A gateway that can never hold one full body would refuse every batch for
// ever, so the pair is refused at startup rather than discovered under load.
func TestAGatewayThatCouldNeverHoldOneBatchIsRefused(t *testing.T) {
	handler, err := ingest.NewHandler(ingest.HandlerOptions{
		Admitter:       newAdmitter(t, &recordingBackbone{}),
		Capacity:       bounded(t, 1<<20, 64),
		Metrics:        ingest.NewMetrics(metrics.New("test")),
		MaxBodyBytes:   8 << 20,
		PublishTimeout: time.Second,
	})
	if err == nil {
		t.Fatalf("a gateway that can never take a batch was built: %v", handler)
	}
}
