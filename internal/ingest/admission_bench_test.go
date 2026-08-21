package ingest_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

// The ceiling the gateway ships with is 10000, so the largest case is the batch
// an agent is actually allowed to send.
var batchSizes = []int{1, 10, 100, 1_000, 5_000, 10_000}

var benchIdentity = agentidentity.Identity{AgentID: "bench-agent-01"}

type discardingBackbone struct{}

func (discardingBackbone) PublishEvents(context.Context, []*eventv1.Event) error { return nil }

func benchAdmitter(b *testing.B) *ingest.Admitter {
	b.Helper()
	admitter, err := ingest.NewAdmitter(
		discardingBackbone{},
		ingest.Policy{
			Gateway:           "bench-gateway",
			TenantID:          "bench",
			MaxEventsPerBatch: 10_000,
			Event:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
		},
		ingest.NewMetrics(metrics.New("bench")),
	)
	if err != nil {
		b.Fatalf("build admitter: %v", err)
	}
	return admitter
}

func benchBatch(size int) *ingestv1.EventBatch {
	at := time.Now().UTC()
	events := make([]*eventv1.Event, 0, size)
	for index := range size {
		events = append(events, fixtures.SSHAuthentication{
			EventID:  fmt.Sprintf("bench-%09d", index),
			At:       at,
			Sequence: uint64(index),
		}.Event())
	}
	return fixtures.Batch("bench-batch", events...)
}

func BenchmarkDecodeBatch(b *testing.B) {
	for _, size := range batchSizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			payload, err := proto.Marshal(benchBatch(size))
			if err != nil {
				b.Fatalf("encode batch: %v", err)
			}

			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				var batch ingestv1.EventBatch
				if err := proto.Unmarshal(payload, &batch); err != nil {
					b.Fatalf("decode batch: %v", err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(size)*float64(b.N)/b.Elapsed().Seconds(), "events/s")
		})
	}
}

func BenchmarkAdmitBatch(b *testing.B) {
	ctx := context.Background()
	for _, size := range batchSizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			admitter := benchAdmitter(b)
			batch := benchBatch(size)

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := admitter.Admit(ctx, benchIdentity, batch); err != nil {
					b.Fatalf("admit: %v", err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(size)*float64(b.N)/b.Elapsed().Seconds(), "events/s")
		})
	}
}
