//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
)

// The whole data plane with nothing stubbed between its ends. Until this passes,
// every other test in the repository is testing a half.
func TestAnAdmittedBatchReachesTheStore(t *testing.T) {
	addresses := brokers(t)
	address := storeAddress(t)
	store := migratedStore(t, address)
	owner := tenant(t)

	topic := temporaryTopic(t, addresses)
	quarantineTopic := temporaryTopic(t, addresses)

	publisher, err := broker.NewPublisher(broker.Config{
		Brokers:  addresses,
		Topic:    topic,
		ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build the publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	admitter, err := ingest.NewAdmitter(publisher, ingest.Policy{
		Gateway:           "gateway-integration",
		TenantID:          owner,
		MaxEventsPerBatch: 100,
		Event:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
	}, ingest.NewMetrics(metrics.New("integration")))
	if err != nil {
		t.Fatalf("build the admitter: %v", err)
	}

	admitCtx, cancelAdmit := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelAdmit()

	at := time.Now().UTC().Truncate(time.Millisecond)
	batch := fixtures.Batch("batch-pipeline",
		fixtures.SSHAuthentication{EventID: "dddddddd-4444-4444-8444-dddddddddddd", At: at, Username: "root"}.Event(),
		fixtures.SSHAuthentication{EventID: "eeeeeeee-5555-4555-8555-eeeeeeeeeeee", At: at, Username: "deploy"}.Event(),
	)
	acknowledgement, err := admitter.Admit(admitCtx, agentidentity.Identity{AgentID: "web-01"}, batch)
	if err != nil {
		t.Fatalf("admit the batch: %v", err)
	}
	if !acknowledgement.GetDurable() {
		t.Fatal("the batch was acknowledged without being made durable")
	}

	writing, stopWriting := context.WithCancel(context.Background())
	defer stopWriting()

	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      addresses,
		Topic:        topic,
		Group:        fmt.Sprintf("event-writer-%d", time.Now().UnixNano()),
		ClientID:     "integration-test",
		MaxRecords:   500,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(metrics.New("integration")),
	})
	if err != nil {
		t.Fatalf("build the consumer: %v", err)
	}
	t.Cleanup(consumer.Close)

	refused, err := broker.NewQuarantine(broker.Config{
		Brokers:  addresses,
		Topic:    quarantineTopic,
		ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build the quarantine publisher: %v", err)
	}
	t.Cleanup(refused.Close)

	writer, err := eventstore.NewWriter(eventstore.WriterOptions{
		Source:        fetchedBy(consumer),
		Sink:          store,
		Quarantine:    quarantineTo(refused),
		Metrics:       eventstore.NewMetrics(metrics.New("integration")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  30 * time.Second,
		RetryDelay:    100 * time.Millisecond,
		MaxRetryDelay: time.Second,
	})
	if err != nil {
		t.Fatalf("build the writer: %v", err)
	}

	stopped := make(chan error, 1)
	go func() { stopped <- writer.Run(writing) }()

	waitFor(t, address, owner, 2)

	stopWriting()
	if err := <-stopped; err != nil && !isCancellation(err) {
		t.Fatalf("the writer stopped with %v", err)
	}

	assertStoredIdentity(t, address, owner, at)
}

func waitFor(t *testing.T, address, owner string, expected uint64) {
	t.Helper()

	inspect := inspector(t, address)
	deadline := time.Now().Add(90 * time.Second)

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var stored uint64
		err := inspect.QueryRow(ctx,
			"SELECT count() FROM security_events FINAL WHERE tenant_id = ?", owner).Scan(&stored)
		cancel()
		if err != nil {
			t.Fatalf("count the stored events: %v", err)
		}
		if stored >= expected {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d admitted events reached the store before the deadline", stored, expected)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// What the gateway stamped has to be what the store holds: a producer cannot
// choose its own tenant, and the platform's timeline survives the trip.
func assertStoredIdentity(t *testing.T, address, owner string, at time.Time) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := inspector(t, address).Query(ctx, `
		SELECT agent_id, gateway, batch_id, event_time, ingest_time, auth_user_name
		FROM security_events FINAL WHERE tenant_id = ? ORDER BY auth_user_name`, owner)
	if err != nil {
		t.Fatalf("read the stored events: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var users []string
	for rows.Next() {
		var agentID, gateway, batchID, username string
		var eventTime, ingestTime time.Time
		if err := rows.Scan(&agentID, &gateway, &batchID, &eventTime, &ingestTime, &username); err != nil {
			t.Fatalf("read a stored event: %v", err)
		}

		if agentID != "web-01" {
			t.Errorf("agent_id is %q: the identity from the certificate did not survive", agentID)
		}
		if gateway != "gateway-integration" || batchID != "batch-pipeline" {
			t.Errorf("reception did not survive: gateway %q batch %q", gateway, batchID)
		}
		if !eventTime.Equal(at) {
			t.Errorf("event_time is %s, want the instant the producer wrote", eventTime)
		}
		if !ingestTime.After(at.Add(-time.Minute)) || ingestTime.Before(at.Add(-time.Second)) {
			t.Errorf("ingest_time is %s, which is not when the platform accepted the event", ingestTime)
		}
		users = append(users, username)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read the stored events: %v", err)
	}

	if len(users) != 2 || users[0] != "deploy" || users[1] != "root" {
		t.Fatalf("the store holds %v, want both admitted events", users)
	}
}

func isCancellation(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}
