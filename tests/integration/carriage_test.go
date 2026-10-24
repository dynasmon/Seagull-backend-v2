//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

// Random rather than repeated, so the broker is handed a batch as large as the
// one the producer built and compression cannot make a ceiling look respected.
func incompressible(size int) []byte {
	random := rand.New(rand.NewPCG(45, 1))
	held := make([]byte, size)
	for index := range held {
		held[index] = byte(random.Uint32())
	}
	return held
}

func provisioned(t *testing.T, addresses []string, topic broker.Topic) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := provisioner(t, addresses).Apply(ctx, []broker.Topic{topic}); err != nil {
		t.Fatalf("apply %s: %v", topic.Name, err)
	}
}

func shippedTopology() broker.Topology {
	return broker.LoadTopology(config.New(func(string) (string, bool) { return "", false }))
}

// A batch of one record, as a broker counts it: a 61-byte header, the record's
// length, its attributes, timestamp and offset deltas, the key and value
// lengths and the header count, then the key and the value themselves.
func largestValueBeside(key int, batch int32) int {
	const header, length, fields = 61, 3, 1 + 1 + 1 + 1 + 3 + 1
	return int(batch) - header - length - fields - key
}

func TestAPublisherCarriesTheLargestBatchItsTopicDeclares(t *testing.T) {
	addresses := brokers(t)
	topic := declaredTopic(t, addresses, 1, 48*time.Hour)
	topic.MaxMessageBytes = 2 << 20
	provisioned(t, addresses, topic)

	refused, err := broker.NewQuarantine(broker.Config{
		Brokers: addresses, Topic: topic.Name, MaxMessageBytes: topic.MaxMessageBytes, ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build the publisher: %v", err)
	}
	t.Cleanup(refused.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	value := incompressible(3 << 19)
	if err := refused.Publish(ctx, []broker.Refused{{Key: []byte("web-01"), Value: value, Reason: "contract_violation"}}); err != nil {
		t.Fatalf("a record of 1.5 MiB was refused on a topic declared to carry 2 MiB: %v", err)
	}
	if held := consume(t, addresses, topic.Name, 1); !bytes.Equal(held[0].Value, value) {
		t.Fatalf("the topic holds %d bytes of the %d published", len(held[0].Value), len(value))
	}
}

func TestAQuarantineTakesTheLargestRecordItsStreamCarries(t *testing.T) {
	addresses := brokers(t)
	shipped := shippedTopology()
	quarantine := declaredTopic(t, addresses, 1, 48*time.Hour)
	quarantine.MaxMessageBytes = shipped.Quarantine.MaxMessageBytes
	provisioned(t, addresses, quarantine)

	refused, err := broker.NewQuarantine(broker.Config{
		Brokers: addresses, Topic: quarantine.Name, MaxMessageBytes: quarantine.MaxMessageBytes, ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build the quarantine publisher: %v", err)
	}
	t.Cleanup(refused.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	key := []byte(strings.Repeat("a", 64))
	largest := incompressible(largestValueBeside(len(key), shipped.Events.MaxMessageBytes))
	if err := refused.Publish(ctx, []broker.Refused{{
		Key:       key,
		Value:     largest,
		Reason:    "contract_violation",
		Detail:    "time.event_time is not a representable instant",
		Partition: 11,
		Offset:    1 << 40,
	}}); err != nil {
		t.Fatalf("a record as large as %s carries could not be quarantined, so the writer refusing it would stop on it: %v",
			shipped.Events.Name, err)
	}
	if held := consume(t, addresses, quarantine.Name, 1); !bytes.Equal(held[0].Value, largest) {
		t.Fatalf("the quarantine holds %d bytes of the %d refused", len(held[0].Value), len(largest))
	}
}
