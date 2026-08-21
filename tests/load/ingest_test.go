//go:build load

package load_test

import (
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

// The whole gateway, over real mutual TLS, against a real backbone. Everything
// below is a decomposition of this number.
func TestSustainedIngestAgainstTheBackbone(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	running := startGateway(t, gatewayOptions{backbone: realBackbone(t, addresses, topic)})

	var outcomes []outcome
	elapsed, allocated, leaked := measure(func() {
		outcomes = drive(t, running, driveOptions{agents: 16, batchSize: 500, duration: 15 * time.Second})
	})

	result := summarise(outcomes, elapsed, allocated, leaked)
	result.report(t, "sustained")

	if result.accepted != result.batches {
		t.Errorf("%d of %d batches were not accepted", result.batches-result.accepted, result.batches)
	}
	if stored := recordsOn(t, addresses, topic); stored != int64(result.events) {
		t.Errorf("the gateway acknowledged %d events and the backbone holds %d", result.events, stored)
	}
}

// The batch ceiling the gateway ships with, sent concurrently. Allocation per
// event is the number that has to stay flat: nothing bounds how many batches
// decode at once, so it is the multiplier on everything else.
func TestConcurrentLargeBatchesHoldTheirAllocationPerEvent(t *testing.T) {
	for _, size := range []int{100, 1_000, 10_000} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			running := startGateway(t, gatewayOptions{})

			var outcomes []outcome
			elapsed, allocated, leaked := measure(func() {
				outcomes = drive(t, running, driveOptions{agents: 32, batchSize: size, batches: 20})
			})

			result := summarise(outcomes, elapsed, allocated, leaked)
			result.report(t, "batch-"+strconv.Itoa(size))

			if result.accepted != result.batches {
				t.Errorf("%d of %d batches were not accepted", result.batches-result.accepted, result.batches)
			}
			if result.bytesPerEvent > 8*1024 {
				t.Errorf("the gateway allocates %.0f bytes per event and the ceiling is 8192", result.bytesPerEvent)
			}
			if result.goroutines > 512 {
				t.Errorf("%d goroutines were still running after the load stopped", result.goroutines)
			}
		})
	}
}

// A backbone that answers slowly must turn into latency at the agent, never
// into an acknowledgement the platform cannot honour.
func TestASlowBackboneBecomesLatencyAndNotLoss(t *testing.T) {
	backbone := newControlledBackbone().keepIdentities()
	backbone.delay = 50 * time.Millisecond
	running := startGateway(t, gatewayOptions{backbone: backbone})

	var outcomes []outcome
	elapsed, allocated, leaked := measure(func() {
		outcomes = drive(t, running, driveOptions{agents: 64, batchSize: 200, batches: 8})
	})

	result := summarise(outcomes, elapsed, allocated, leaked)
	result.report(t, "slow-backbone")
	t.Logf("slow-backbone: %d publishes were in flight at once", backbone.peak.Load())

	for _, entry := range outcomes {
		if entry.status != http.StatusOK {
			continue
		}
		for _, record := range entry.batch.GetEvents() {
			if !backbone.holds(record.GetEventId()) {
				t.Fatalf("%s was acknowledged and the backbone never received it", record.GetEventId())
			}
		}
	}
	if backbone.peak.Load() < 2 {
		t.Error("the load never reached the gateway concurrently, so it measured nothing")
	}
}

// The per-agent budget exists so that one captured agent cannot spend the
// gateway. The agents beside it must not notice.
func TestAnAbusiveAgentDoesNotSpendTheBudgetOfOthers(t *testing.T) {
	running := startGateway(t, gatewayOptions{
		backbone:      newControlledBackbone(),
		ratePerSecond: 50,
		rateBurst:     50,
	})

	var abusive, ordinary []outcome
	var group sync.WaitGroup
	group.Add(2)

	go func() {
		defer group.Done()
		abusive = drive(t, running, driveOptions{agents: 1, batchSize: 100, batches: 400})
	}()
	go func() {
		defer group.Done()
		ordinary = drive(t, running, driveOptions{agents: 4, batchSize: 100, batches: 20, prefix: "quiet-agent"})
	}()
	group.Wait()

	refused := 0
	for _, entry := range abusive {
		if entry.status == http.StatusTooManyRequests {
			refused++
		}
	}
	t.Logf("abusive agent: %d of %d batches refused", refused, len(abusive))

	if refused == 0 {
		t.Error("the abusive agent was never refused, so the budget did nothing")
	}
	for _, entry := range ordinary {
		if entry.status != http.StatusOK {
			t.Fatalf("an agent beside the abusive one was answered %d", entry.status)
		}
	}
}

// Nothing the gateway has already answered may disappear when it stops.
func TestShutdownUnderLoadKeepsEveryAcknowledgedBatch(t *testing.T) {
	backbone := newControlledBackbone().keepIdentities()
	backbone.delay = 5 * time.Millisecond
	running := startGateway(t, gatewayOptions{backbone: backbone})

	outcomes := make(chan []outcome, 1)
	go func() {
		outcomes <- drive(t, running, driveOptions{agents: 24, batchSize: 250, batches: 200, tolerant: true})
	}()

	time.Sleep(2 * time.Second)
	running.stop()

	if err := running.awaitStop(30 * time.Second); err != nil {
		t.Fatalf("the gateway stopped badly under load: %v", err)
	}

	answered := 0
	for _, entry := range <-outcomes {
		if entry.status != http.StatusOK {
			continue
		}
		answered++
		for _, record := range entry.batch.GetEvents() {
			if !backbone.holds(record.GetEventId()) {
				t.Fatalf("%s was acknowledged and then lost to the shutdown", record.GetEventId())
			}
		}
	}
	t.Logf("shutdown: %d batches were acknowledged before the stop and every one survived it", answered)

	if answered == 0 {
		t.Error("the gateway stopped before it accepted anything, so it measured nothing")
	}
}
