//go:build integration

package integration_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func liveness(t *testing.T, address string, horizon time.Duration) *clickhouse.Liveness {
	t.Helper()

	reader, err := clickhouse.NewLiveness(storeSettings(address), horizon)
	if err != nil {
		t.Fatalf("build the liveness reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	return reader
}

func sentBy(agentID, tenant, id string, at time.Time) *eventv1.Event {
	record := admitted(tenant, id, "root", at)
	record.Origin.AgentId = agentID
	record.Reception.IngestTime = timestamppb.New(at)
	return record
}

// When an agent was last heard from is a question about the stream, answered
// where the stream landed. An agent that sent nothing is absent rather than
// wrong, and one in another tenant is not there at all.
func TestWhenAnAgentWasLastHeardFromIsReadFromTheTelemetry(t *testing.T) {
	address := storeAddress(t)
	store := migratedStore(t, address)
	reader := liveness(t, address, 720*time.Hour)

	now := time.Now().UTC().Truncate(time.Second)
	talkative, silent := agentIdentifier(t), agentIdentifier(t)
	elsewhere := agentIdentifier(t)

	keep(t, store,
		sentBy(talkative, "liveness-tenant", talkative+"-1", now.Add(-2*time.Hour)),
		sentBy(talkative, "liveness-tenant", talkative+"-2", now.Add(-time.Hour)),
		sentBy(elsewhere, "another-tenant", elsewhere+"-1", now.Add(-time.Hour)),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seen, err := reader.LastSeen(ctx,
		[]string{talkative, silent, elsewhere}, []string{"liveness-tenant"})
	if err != nil {
		t.Fatalf("read when agents were last seen: %v", err)
	}

	at, found := seen[talkative]
	if !found {
		t.Fatalf("an agent that sent telemetry was never seen: %v", seen)
	}
	if at.Before(now.Add(-time.Hour - time.Minute)) {
		t.Fatalf("the latest arrival was not the answer: %s", at)
	}
	if _, found := seen[silent]; found {
		t.Fatal("an agent that sent nothing was reported alive")
	}
	if _, found := seen[elsewhere]; found {
		t.Fatal("an agent in another tenant was answered about")
	}
}

func TestNothingOlderThanTheHorizonIsRead(t *testing.T) {
	address := storeAddress(t)
	store := migratedStore(t, address)

	now := time.Now().UTC().Truncate(time.Second)
	agentID := agentIdentifier(t)
	keep(t, store, sentBy(agentID, "liveness-tenant", agentID+"-old", now.Add(-48*time.Hour)))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seen, err := liveness(t, address, time.Hour).LastSeen(ctx, []string{agentID}, []string{"liveness-tenant"})
	if err != nil {
		t.Fatalf("read when agents were last seen: %v", err)
	}
	if _, found := seen[agentID]; found {
		t.Fatal("an arrival older than the horizon was read")
	}

	seen, err = liveness(t, address, 720*time.Hour).LastSeen(ctx, []string{agentID}, []string{"liveness-tenant"})
	if err != nil {
		t.Fatalf("read when agents were last seen: %v", err)
	}
	if _, found := seen[agentID]; !found {
		t.Fatal("a wider horizon did not reach the arrival")
	}
}

func TestAskingAboutNobodyReadsNothing(t *testing.T) {
	address := storeAddress(t)
	reader := liveness(t, address, time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, asked := range []struct{ agents, tenants []string }{
		{nil, []string{"liveness-tenant"}},
		{[]string{"web-01"}, nil},
	} {
		seen, err := reader.LastSeen(ctx, asked.agents, asked.tenants)
		if err != nil {
			t.Fatalf("read when agents were last seen: %v", err)
		}
		if len(seen) != 0 {
			t.Fatalf("a query with nothing to ask about answered %d rows", len(seen))
		}
	}
}
