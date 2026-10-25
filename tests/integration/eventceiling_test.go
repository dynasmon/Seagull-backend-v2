//go:build integration

package integration_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func TestAnEventWeighingTheCeilingIsMadeDurableAndOneByteMoreIsRefused(t *testing.T) {
	addresses := brokers(t)
	topic := declaredTopic(t, addresses, 3, 48*time.Hour)
	topic.MaxMessageBytes = shippedTopology().Events.MaxMessageBytes
	provisioned(t, addresses, topic)

	publisher, err := broker.NewPublisher(broker.Config{
		Brokers: addresses, Topic: topic.Name, MaxMessageBytes: topic.MaxMessageBytes, ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	received := time.Now().UTC().Truncate(time.Second)
	admitter, err := ingest.NewAdmitter(publisher, ingest.Policy{
		Gateway:           "gateway-integration",
		MaxEventsPerBatch: 100,
		Event:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
	}, ingest.NewMetrics(metrics.New("integration")), ingest.WithClock(func() time.Time { return received }))
	if err != nil {
		t.Fatalf("build admitter: %v", err)
	}

	widestAgent := strings.Repeat("a", event.MaxAgentIDLength)
	weighing := func(size int) *eventv1.Event {
		record := fixtures.SSHAuthentication{AgentID: widestAgent, At: received.Add(-time.Second)}.Event()
		record.Origin.TenantId = "acme"
		record.Reception = &eventv1.Reception{IngestTime: timestamppb.New(received), Gateway: "gateway-integration", BatchId: "batch-ceiling"}
		if !fixtures.Bloat(record, size) {
			t.Fatalf("no event encodes to %d bytes", size)
		}
		return record
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	identity := agentidentity.Identity{AgentID: widestAgent}

	if _, err := admitter.Admit(ctx, identity, "acme", fixtures.Batch("batch-ceiling", weighing(event.MaxEventBytes))); err != nil {
		t.Fatalf("an event weighing the ceiling under the widest key was answered %v", err)
	}
	if held := consume(t, addresses, topic.Name, 1); len(held[0].Value) != event.MaxEventBytes {
		t.Fatalf("the backbone holds an event of %d bytes", len(held[0].Value))
	}

	_, err = admitter.Admit(ctx, identity, "acme", fixtures.Batch("batch-ceiling", weighing(event.MaxEventBytes+1)))
	var rejection *ingest.Rejection
	if !errors.As(err, &rejection) || rejection.Code != ingest.CodeInvalidEvent || rejection.EventIndex != 0 {
		t.Fatalf("an event one byte above the ceiling was answered %v rather than refused by its position", err)
	}
}
