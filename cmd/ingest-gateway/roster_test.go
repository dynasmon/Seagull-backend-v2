package main

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func admissionRecord(t *testing.T, key string, record *agentv1.Admission) broker.Record {
	t.Helper()

	encoded, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode an admission: %v", err)
	}
	return broker.Record{Key: []byte(key), Value: encoded}
}

func reading(t *testing.T) (roster, broker.Deliver) {
	t.Helper()

	held := roster{held: agent.NewRoster()}
	return held, held.applying(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
}

// The compacted log keeps one record per agent, so the record a reader cannot
// decode is the whole of what the platform decided about it: stepping over it
// would re-admit the certificate that record revoked.
func TestARecordTheGatewayCannotDecodeStopsTheAgentItIsKeyedBy(t *testing.T) {
	held, apply := reading(t)

	if err := apply(context.Background(), []broker.Record{{Key: []byte("web-01"), Value: []byte{0xff, 0xfe}}}); err != nil {
		t.Fatalf("an unreadable record ended the replay: %v", err)
	}
	if held.held.Admits("web-01") {
		t.Error("an agent whose record could not be decoded is still admitted")
	}
	if !held.held.Admits("web-02") {
		t.Error("refusing one agent refused another")
	}
}

// A state this build does not know reads as no decision at all, which is not a
// reason to believe the agent is still admitted.
func TestARecordNamingAStateThisBuildCannotReadStopsTheAgent(t *testing.T) {
	held, apply := reading(t)

	unknown := admissionRecord(t, "web-01", &agentv1.Admission{AgentId: "web-01", State: agentv1.State(99), Revision: 4})
	if err := apply(context.Background(), []broker.Record{unknown}); err != nil {
		t.Fatalf("a record naming an unknown state ended the replay: %v", err)
	}
	if held.held.Admits("web-01") {
		t.Error("an agent whose state this build cannot read is still admitted")
	}
}

// Applying a record under either name would decide for an agent the control
// plane did not write about, so the record decides for neither and stops the one
// it is filed under.
func TestARecordWhoseKeyAndPayloadDisagreeStopsTheAgentItIsKeyedBy(t *testing.T) {
	held, apply := reading(t)

	crossed := admissionRecord(t, "web-01", &agentv1.Admission{AgentId: "db-07", State: agent.Active.Wire(), Revision: 2})
	if err := apply(context.Background(), []broker.Record{crossed}); err != nil {
		t.Fatalf("a mismatched record ended the replay: %v", err)
	}
	if held.held.Admits("web-01") {
		t.Error("the agent the record was keyed by is still admitted")
	}
	if held.held.Known() != 1 {
		t.Errorf("the roster decided about %d agents", held.held.Known())
	}
}

// A record naming no agent can neither be applied nor be refused on anybody's
// behalf, so the process stays out of service rather than serving from a
// registry it knows is incomplete.
func TestARecordNamingNoAgentEndsTheReplay(t *testing.T) {
	_, apply := reading(t)

	if err := apply(context.Background(), []broker.Record{{Value: []byte{0xff, 0xfe}}}); err == nil {
		t.Fatal("a record naming no agent left the gateway serving")
	}
}

func TestAReadableRecordIsApplied(t *testing.T) {
	held, apply := reading(t)

	revoked := admissionRecord(t, "web-01", &agentv1.Admission{AgentId: "web-01", State: agent.Revoked.Wire(), Revision: 9})
	if err := apply(context.Background(), []broker.Record{revoked}); err != nil {
		t.Fatalf("apply a readable record: %v", err)
	}
	if held.held.Admits("web-01") {
		t.Error("a revoked agent is still admitted")
	}
}
