//go:build integration

package integration_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
)

func carved() detectionstate.Bounds {
	return detectionstate.Bounds{
		Window:             time.Hour,
		ObservationsPerKey: 128,
		Keys:               8,
		KeysPerTenant:      4,
		KeysPerRule:        4,
	}
}

// A flood as an agent sends one: every event from an address nobody saw before.
func admitInventedAddresses(t *testing.T, addresses []string, topic, owner, agent string, count int, at time.Time) {
	t.Helper()

	batch := fixtures.Batch("batch-" + agent)
	for index := range count {
		batch.Events = append(batch.Events, fixtures.SSHAuthentication{
			EventID:  fmt.Sprintf("%s-%09d", agent, index),
			At:       at,
			SourceIP: fmt.Sprintf("198.18.0.%d", index),
			Sequence: uint64(index),
		}.Event())
	}
	admitBatch(t, addresses, topic, owner, agent, batch)
}

func TestATenantFloodingGroupValuesLeavesAnotherTenantsRuleDeciding(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	found := temporaryTopic(t, addresses)
	group := fmt.Sprintf("analysis-engine-%d", time.Now().UnixNano())
	at := time.Now().UTC()

	admitInventedAddresses(t, addresses, topic, tenant(t), "flooding-agent", 64, at)
	admitAt(t, addresses, topic, tenant(t), "another-agent", 0, 20, at)

	start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: acrossARestart(t), bounds: carved(),
	})

	if made := detected(t, addresses, found, 1, 30*time.Second); made == 0 {
		t.Fatal("twenty failures beside another tenant's flood made no detection against a threshold of twenty")
	}
}

// What ADR 36 promises, under the pressure this record adds: the flood is read
// back with everything else, and the window of the tenant beside it is rebuilt
// from the same partitions as if nothing had been refused.
func TestARestartBesideAFloodStillReachesTheThreshold(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	found := temporaryTopic(t, addresses)
	group := fmt.Sprintf("analysis-engine-%d", time.Now().UnixNano())
	flooding, another := tenant(t), tenant(t)
	at := time.Now().UTC()

	admitInventedAddresses(t, addresses, topic, flooding, "flooding-agent", 64, at)
	admitAt(t, addresses, topic, another, "another-agent", 0, 15, at)

	first := start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: acrossARestart(t), recover: time.Hour, bounds: carved(),
	})
	awaitCommitted(t, addresses, topic, group, 79)
	first.terminate(t)
	if made := detected(t, addresses, found, 1, 2*time.Second); made != 0 {
		t.Fatalf("fifteen failures made %d detections before the restart", made)
	}

	admitAt(t, addresses, topic, another, "another-agent", 15, 5, at)

	start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: acrossARestart(t), recover: time.Hour, bounds: carved(),
	})

	if made := detected(t, addresses, found, 1, 30*time.Second); made == 0 {
		t.Fatal("twenty failures split by a restart beside a flood made no detection against a threshold of twenty")
	}
}
