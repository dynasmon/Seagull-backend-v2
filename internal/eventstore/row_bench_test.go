package eventstore_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func admitted() *eventv1.Event {
	at := time.Now().UTC()
	record := fixtures.SSHAuthentication{At: at}.Event()
	record.Reception = &eventv1.Reception{
		IngestTime: timestamppb.New(at),
		Gateway:    "bench-gateway",
		BatchId:    "bench-batch",
	}
	return record
}

func BenchmarkProject(b *testing.B) {
	record := admitted()

	b.ReportAllocs()
	for range b.N {
		if row := eventstore.Project(record); row.EventID == "" {
			b.Fatal("the projection dropped the event identity")
		}
	}
}

// What the writer pays for one record off the backbone before it reaches the
// store: decode, then project.
func BenchmarkDecodeAndProject(b *testing.B) {
	payload, err := proto.Marshal(admitted())
	if err != nil {
		b.Fatalf("encode event: %v", err)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for range b.N {
		var record eventv1.Event
		if err := proto.Unmarshal(payload, &record); err != nil {
			b.Fatalf("decode event: %v", err)
		}
		if row := eventstore.Project(&record); row.EventID == "" {
			b.Fatal("the projection dropped the event identity")
		}
	}
}
