//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func compactedAgentTopic(t *testing.T, addresses []string) string {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	t.Cleanup(client.Close)

	admin := kadm.NewClient(client)
	topic := fmt.Sprintf("security.agents.test.%d", time.Now().UnixNano())
	compact, forever := "compact", "-1"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	settings := map[string]*string{"cleanup.policy": &compact, "retention.ms": &forever}
	if _, err := admin.CreateTopic(ctx, 1, 1, settings, topic); err != nil {
		t.Fatalf("create topic: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.DeleteTopics(cleanup, topic)
	})
	return topic
}

func rosterFrom(t *testing.T, addresses []string, topic string) *agent.Roster {
	t.Helper()

	reader, err := broker.NewStateLog(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"}, 64)
	if err != nil {
		t.Fatalf("build an admission reader: %v", err)
	}
	t.Cleanup(reader.Close)

	held := agent.NewRoster()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = reader.Replay(ctx, func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			var admission agentv1.Admission
			if err := proto.Unmarshal(record.Value, &admission); err != nil {
				return err
			}
			if err := held.Apply(&admission); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("replay the admission log: %v", err)
	}
	return held
}

// What the control plane decided about an agent is what a gateway that was not
// running finds when it starts. This is the whole of the propagation: no
// process reads the registry, and neither names the other.
func TestARevokedAgentIsRefusedByAGatewayThatWasNotRunning(t *testing.T) {
	addresses := brokers(t)
	topic := compactedAgentTopic(t, addresses)

	publisher, err := broker.NewAgents(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build an admission publisher: %v", err)
	}
	defer publisher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, record := range []*agentv1.Admission{
		{AgentId: "it-web-01", TenantId: "default", State: agent.Pending.Wire(), Revision: 1},
		{AgentId: "it-web-01", TenantId: "default", State: agent.Active.Wire(), Revision: 2},
		{AgentId: "it-db-07", TenantId: "default", State: agent.Active.Wire(), Revision: 2},
		{AgentId: "it-db-07", TenantId: "default", State: agent.Revoked.Wire(), Revision: 3},
	} {
		if err := publisher.Publish(ctx, record); err != nil {
			t.Fatalf("publish %s: %v", record.GetAgentId(), err)
		}
	}

	held := rosterFrom(t, addresses, topic)
	if _, admits := held.Tenant("it-web-01"); !admits {
		t.Fatal("an active agent is refused")
	}
	if _, admits := held.Tenant("it-db-07"); admits {
		t.Fatal("a revoked agent is admitted")
	}
	if tenant, admits := held.Tenant("it-never-registered"); admits {
		t.Fatalf("an agent the registry never named is admitted into %q", tenant)
	}
	if held.Refused() != 1 {
		t.Fatalf("the roster refuses %d agents", held.Refused())
	}
}

func TestAGatewayThatWasNotRunningPlacesEachAgentInTheTenantTheRegistryRecorded(t *testing.T) {
	addresses := brokers(t)
	topic := compactedAgentTopic(t, addresses)

	publisher, err := broker.NewAgents(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build an admission publisher: %v", err)
	}
	defer publisher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, record := range []*agentv1.Admission{
		{AgentId: "it-web-03", TenantId: "acme", State: agent.Active.Wire(), Revision: 2},
		{AgentId: "it-db-04", TenantId: "globex", State: agent.Pending.Wire(), Revision: 1},
	} {
		if err := publisher.Publish(ctx, record); err != nil {
			t.Fatalf("publish %s: %v", record.GetAgentId(), err)
		}
	}

	held := rosterFrom(t, addresses, topic)
	for agentID, want := range map[string]string{"it-web-03": "acme", "it-db-04": "globex"} {
		if tenant, admits := held.Tenant(agentID); !admits || tenant != want {
			t.Errorf("%s is admitted %t into %q, and the registry recorded it in %q", agentID, admits, tenant, want)
		}
	}
}

func TestAnAgentLetInAgainIsAdmittedByAGatewayThatStartsAfterwards(t *testing.T) {
	addresses := brokers(t)
	topic := compactedAgentTopic(t, addresses)

	publisher, err := broker.NewAgents(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build an admission publisher: %v", err)
	}
	defer publisher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, record := range []*agentv1.Admission{
		{AgentId: "it-web-02", TenantId: "default", State: agent.Disabled.Wire(), Revision: 2},
		{AgentId: "it-web-02", TenantId: "default", State: agent.Active.Wire(), Revision: 3},
	} {
		if err := publisher.Publish(ctx, record); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}

	if _, admits := rosterFrom(t, addresses, topic).Tenant("it-web-02"); !admits {
		t.Fatal("a re-enabled agent is still refused")
	}

	if err := publisher.Publish(ctx, &agentv1.Admission{AgentId: ""}); err == nil {
		t.Fatal("a record naming no agent was published")
	}
}
