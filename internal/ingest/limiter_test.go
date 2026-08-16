package ingest_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/dynasmon/Seagull-v2/internal/ingest"
)

func TestBurstIsAllowedAndTheRestIsRefused(t *testing.T) {
	limiter := ingest.NewLimiter(1, 3, 100)

	for attempt := range 3 {
		if !limiter.Allow("web-01") {
			t.Fatalf("attempt %d inside the burst was refused", attempt)
		}
	}
	if limiter.Allow("web-01") {
		t.Fatal("the agent was allowed past its burst")
	}
}

func TestAgentsHaveSeparateBudgets(t *testing.T) {
	limiter := ingest.NewLimiter(1, 1, 100)

	if !limiter.Allow("web-01") || !limiter.Allow("web-02") {
		t.Fatal("agents must not share a budget")
	}
	if limiter.Allow("web-01") {
		t.Fatal("the first agent kept spending after its budget ran out")
	}
}

func TestTrackedAgentsAreBounded(t *testing.T) {
	limiter := ingest.NewLimiter(100, 100, 8)

	for index := range 1000 {
		limiter.Allow(fmt.Sprintf("agent-%d", index))
	}

	if tracked := limiter.Tracked(); tracked > 8 {
		t.Fatalf("the limiter tracked %d agents with a ceiling of 8", tracked)
	}
}

func TestZeroRateDisablesTheLimiter(t *testing.T) {
	limiter := ingest.NewLimiter(0, 0, 8)

	for range 1000 {
		if !limiter.Allow("web-01") {
			t.Fatal("a disabled limiter must not refuse anything")
		}
	}
	if limiter.Tracked() != 0 {
		t.Fatal("a disabled limiter must not allocate per-agent state")
	}
}

func TestNilLimiterAllows(t *testing.T) {
	var limiter *ingest.Limiter
	if !limiter.Allow("web-01") {
		t.Fatal("an absent limiter must not refuse")
	}
}

func TestLimiterIsSafeUnderConcurrency(t *testing.T) {
	limiter := ingest.NewLimiter(1000, 1000, 16)

	var group sync.WaitGroup
	for worker := range 32 {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for index := range 100 {
				limiter.Allow(fmt.Sprintf("agent-%d", (worker+index)%64))
			}
		}(worker)
	}
	group.Wait()

	if tracked := limiter.Tracked(); tracked > 16 {
		t.Fatalf("the limiter grew past its ceiling under concurrency: %d", tracked)
	}
}
