package broker

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// What the gateway pays to put a batch on the wire, after having just decoded
// the same events: a stamped event is re-encoded before it is produced.
func BenchmarkEncodeBatch(b *testing.B) {
	for _, size := range []int{1, 10, 100, 1_000, 5_000, 10_000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			at := time.Now().UTC()
			events := make([]*eventv1.Event, 0, size)
			for index := range size {
				events = append(events, fixtures.SSHAuthentication{
					EventID:  fmt.Sprintf("bench-%09d", index),
					At:       at,
					Sequence: uint64(index),
				}.Event())
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				records, err := encode("security.events.raw", events)
				if err != nil {
					b.Fatalf("encode batch: %v", err)
				}
				if len(records) != size {
					b.Fatalf("encoded %d records and the batch carries %d", len(records), size)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(size)*float64(b.N)/b.Elapsed().Seconds(), "events/s")
		})
	}
}
