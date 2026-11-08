//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

func everyPartitionOrNone(partitions map[string]int32) broker.Ownership {
	return func(held map[string]int32) error {
		total, holding := int32(0), int32(0)
		for topic, declared := range partitions {
			total += declared
			holding += held[topic]
		}
		if holding != 0 && holding != total {
			return fmt.Errorf("this reader holds %d of the %d partitions it has to read alone", holding, total)
		}
		return nil
	}
}

func produceTo(t *testing.T, addresses []string, records ...*kgo.Record) {
	t.Helper()
	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.ProduceSync(ctx, records...).FirstErr(); err != nil {
		t.Fatalf("produce: %v", err)
	}
}

type delivered struct {
	mu      sync.Mutex
	records []broker.Record
}

func (d *delivered) deliver(_ context.Context, records []broker.Record) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records = append(d.records, records...)
	return nil
}

func (d *delivered) from(topic string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	count := 0
	for _, record := range d.records {
		if record.Topic == topic {
			count++
		}
	}
	return count
}

func readerOf(t *testing.T, addresses []string, group string, ownership broker.Ownership, topics ...string) *broker.Consumer {
	t.Helper()
	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      addresses,
		Topics:       topics,
		Group:        group,
		ClientID:     "integration-test",
		MaxRecords:   64,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(metrics.New("integration")),
		Ownership:    ownership,
	})
	if err != nil {
		t.Fatalf("build the consumer: %v", err)
	}
	t.Cleanup(consumer.Close)
	return consumer
}

func TestOneReaderOfTwoTopicsDeliversBothInOneLoopAndCommitsBoth(t *testing.T) {
	addresses := brokers(t)
	inventory, advisories := temporaryTopic(t, addresses), temporaryTopic(t, addresses)
	group := fmt.Sprintf("vulnerability-matcher-%d", time.Now().UnixNano())

	produceTo(t, addresses,
		&kgo.Record{Topic: inventory, Key: []byte("web-01"), Value: []byte("scan")},
		&kgo.Record{Topic: inventory, Key: []byte("db-01"), Value: []byte("scan")},
		&kgo.Record{Topic: advisories, Key: []byte("advisory/osv/DSA-5764-1"), Value: []byte("advisory")},
	)

	got := &delivered{}
	consumer := readerOf(t, addresses, group, everyPartitionOrNone(map[string]int32{inventory: 3, advisories: 3}), inventory, advisories)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	stopped := make(chan error, 1)
	go func() { stopped <- consumer.Consume(ctx, got.deliver) }()

	awaitCommitted(t, addresses, inventory, group, 2)
	awaitCommitted(t, addresses, advisories, group, 1)
	stop()
	if err := <-stopped; err != nil && !isCancellation(err) {
		t.Fatalf("a reader holding every partition of both topics stopped with %v", err)
	}
	if got.from(inventory) != 2 || got.from(advisories) != 1 {
		t.Fatalf("the reader delivered %d records of %s and %d of %s", got.from(inventory), inventory, got.from(advisories), advisories)
	}
}

func bothStopRefused(t *testing.T, readers map[string]chan error) {
	t.Helper()
	for name, stopped := range readers {
		select {
		case err := <-stopped:
			if err == nil || !errorMentions(err, "read alone") {
				t.Errorf("the %s reader stopped with %v", name, err)
			}
		case <-time.After(90 * time.Second):
			t.Fatalf("the %s reader is still reading what it has to read alone, beside another", name)
		}
	}
}

// Nothing arrives after the second reader joins, so neither is woken by a
// record: a refusal has to stop a reader that is only waiting.
func TestAReaderLeftWithPartOfWhatItReadsAloneStopsWithNothingToRead(t *testing.T) {
	addresses := brokers(t)
	inventory, advisories := temporaryTopic(t, addresses), temporaryTopic(t, addresses)
	group := fmt.Sprintf("vulnerability-matcher-%d", time.Now().UnixNano())
	alone := everyPartitionOrNone(map[string]int32{inventory: 3, advisories: 3})

	produceTo(t, addresses, &kgo.Record{Topic: inventory, Key: []byte("web-01"), Value: []byte("scan")})
	first := readerOf(t, addresses, group, alone, inventory, advisories)
	firstStopped := make(chan error, 1)
	go func() { firstStopped <- first.Consume(context.Background(), (&delivered{}).deliver) }()
	awaitCommitted(t, addresses, inventory, group, 1)

	second := readerOf(t, addresses, group, alone, inventory, advisories)
	secondStopped := make(chan error, 1)
	go func() { secondStopped <- second.Consume(context.Background(), (&delivered{}).deliver) }()

	bothStopRefused(t, map[string]chan error{"first": firstStopped, "second": secondStopped})
}

// Records keep arriving on every partition while the second reader joins, so
// whatever the group hands it has something to fetch; it delivers none of it.
func TestAReaderThatJoinsWhatAnotherReadsAloneDeliversNothing(t *testing.T) {
	addresses := brokers(t)
	inventory, advisories := temporaryTopic(t, addresses), temporaryTopic(t, addresses)
	group := fmt.Sprintf("vulnerability-matcher-%d", time.Now().UnixNano())
	alone := everyPartitionOrNone(map[string]int32{inventory: 3, advisories: 3})

	produceTo(t, addresses, &kgo.Record{Topic: inventory, Key: []byte("web-01"), Value: []byte("scan")})
	first := readerOf(t, addresses, group, alone, inventory, advisories)
	firstStopped := make(chan error, 1)
	go func() { firstStopped <- first.Consume(context.Background(), (&delivered{}).deliver) }()
	awaitCommitted(t, addresses, inventory, group, 1)

	producer, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	defer producer.Close()
	producing, stopProducing := context.WithCancel(context.Background())
	produced := make(chan struct{})
	go func() {
		defer close(produced)
		for round := 0; producing.Err() == nil; round++ {
			var batch []*kgo.Record
			for index := range 12 {
				key := []byte(fmt.Sprintf("agent-%d-%d", round, index))
				batch = append(batch, &kgo.Record{Topic: inventory, Key: key, Value: []byte("scan")},
					&kgo.Record{Topic: advisories, Key: key, Value: []byte("advisory")})
			}
			if err := producer.ProduceSync(producing, batch...).FirstErr(); err != nil && producing.Err() == nil {
				t.Errorf("produce while the second reader joins: %v", err)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	joined := &delivered{}
	second := readerOf(t, addresses, group, alone, inventory, advisories)
	secondStopped := make(chan error, 1)
	go func() { secondStopped <- second.Consume(context.Background(), joined.deliver) }()

	bothStopRefused(t, map[string]chan error{"first": firstStopped, "second": secondStopped})
	stopProducing()
	<-produced
	if count := joined.from(inventory) + joined.from(advisories); count != 0 {
		t.Fatalf("the reader that joined delivered %d records while another held part of the topics", count)
	}
}
