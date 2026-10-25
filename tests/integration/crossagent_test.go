//go:build integration

package integration_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func acrossAgents(t *testing.T) *detection.Program {
	t.Helper()

	program, err := detection.Compile(detection.Rule{
		ID:          "authentication.repeated_failures_across_agents",
		Revision:    1,
		Name:        "Repeated authentication failures from one address across agents",
		Description: "More failures from one address against the whole estate than it should see.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue("failure")},
		},
		Count: detection.Count{
			AtLeast: 10,
			Within:  10 * time.Minute,
			GroupBy: []detection.Field{"authentication.network.source.ip"},
		},
		Severity: detection.High,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("compile the rule: %v", err)
	}
	return program
}

func TestASoleReaderCountsTwoAgentsSendingOneEventIdentifierApart(t *testing.T) {
	addresses := brokers(t)
	topic := temporaryTopic(t, addresses)
	found := temporaryTopic(t, addresses)
	group := fmt.Sprintf("analysis-engine-%d", time.Now().UnixNano())
	owner := tenant(t)
	at := time.Now().UTC()

	admitNamed(t, addresses, topic, owner, "web-01", "shared", 0, 5, at)
	admitNamed(t, addresses, topic, owner, "web-02", "shared", 0, 5, at)

	start(t, replicaOptions{
		addresses: addresses, topic: topic, found: found, group: group,
		program: acrossAgents(t), recover: time.Minute, sole: true,
	})

	if made := detected(t, addresses, found, 1, 30*time.Second); made == 0 {
		t.Fatal("ten failures two agents sent under five shared identifiers made no detection against a threshold of ten")
	}
}
