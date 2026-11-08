//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
)

func positionsOf(t *testing.T, addresses []string) *broker.Positions {
	t.Helper()
	positions, err := broker.NewPositions(addresses, "integration-test", broker.Security{})
	if err != nil {
		t.Fatalf("build the positions reader: %v", err)
	}
	t.Cleanup(positions.Close)
	return positions
}

func sum(offsets map[int32]int64) int64 {
	var total int64
	for _, offset := range offsets {
		total += offset
	}
	return total
}

// What a reader of a store waits on: the owner's committed offsets reach the
// end of what was published only once the owner has made all of it durable.
func TestAnOwnersPositionIsWhereItCommittedAndATopicEndsWhereItWasWritten(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	owner := fmt.Sprintf("inventory-projector-%d", time.Now().UnixNano())
	positions := positionsOf(t, addresses)

	var published []*kgo.Record
	for index := range 9 {
		published = append(published, &kgo.Record{Topic: topic, Key: []byte(fmt.Sprintf("agent-%d", index)), Value: []byte("scan")})
	}
	produceTo(t, addresses, published...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ends, err := positions.Ends(ctx, topic)
	if err != nil || len(ends) != 3 || sum(ends) != 9 {
		t.Fatalf("%s ends at %v (%v), and nine records were written to its three partitions", topic, ends, err)
	}
	before, err := positions.Committed(ctx, owner, topic)
	if err != nil || len(before) != 0 {
		t.Fatalf("a group that never read %s stands at %v (%v)", topic, before, err)
	}

	reading, stop := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	reader := readerOf(t, addresses, owner, nil, topic)
	go func() { stopped <- reader.Consume(reading, (&delivered{}).deliver) }()
	awaitCommitted(t, addresses, topic, owner, 9)
	stop()
	if err := <-stopped; err != nil && !isCancellation(err) {
		t.Fatalf("the owner stopped with %v", err)
	}

	after, err := positions.Committed(ctx, owner, topic)
	if err != nil {
		t.Fatalf("read where the owner stands: %v", err)
	}
	for partition, end := range ends {
		if after[partition] != end {
			t.Errorf("the owner stands at %d on partition %d, which ends at %d", after[partition], partition, end)
		}
	}
	if other, err := positions.Committed(ctx, owner, temporaryTopic(t, addresses)); err != nil || len(other) != 0 {
		t.Errorf("the owner stands at %v (%v) on a topic it never read", other, err)
	}
}

func TestATopicTheBackboneDoesNotHaveHasNoEnd(t *testing.T) {
	positions := positionsOf(t, brokers(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if ends, err := positions.Ends(ctx, fmt.Sprintf("security.missing.%d", time.Now().UnixNano())); err == nil {
		t.Fatalf("a missing topic ends at %v", ends)
	}
}
