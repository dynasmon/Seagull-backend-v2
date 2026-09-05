//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
)

func administrator(t *testing.T, addresses []string) *kadm.Client {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	t.Cleanup(client.Close)
	return kadm.NewClient(client)
}

func declaredTopic(t *testing.T, addresses []string, partitions int32, retention time.Duration) broker.Topic {
	t.Helper()

	name := fmt.Sprintf("security.events.topology.test.%d", time.Now().UnixNano())
	admin := administrator(t, addresses)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.DeleteTopics(ctx, name)
	})

	return broker.Topic{
		Name:        name,
		Partitions:  partitions,
		Replicas:    1,
		Retention:   retention,
		Cleanup:     "delete",
		Compression: "zstd",
		MinInSync:   1,
	}
}

func provisioner(t *testing.T, addresses []string) *broker.Provisioner {
	t.Helper()

	provisioner, err := broker.NewProvisioner(addresses, "integration-test", broker.Security{})
	if err != nil {
		t.Fatalf("build provisioner: %v", err)
	}
	t.Cleanup(provisioner.Close)
	return provisioner
}

func shapeOf(t *testing.T, addresses []string, name string) (int32, map[string]string) {
	t.Helper()

	admin := administrator(t, addresses)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	listed, err := admin.ListTopics(ctx, name)
	if err != nil {
		t.Fatalf("read the topology: %v", err)
	}
	detail, found := listed[name]
	if !found || detail.Err != nil {
		t.Fatalf("read %s: not present", name)
	}

	described, err := admin.DescribeTopicConfigs(ctx, name)
	if err != nil {
		t.Fatalf("read the configuration of %s: %v", name, err)
	}
	resource, err := described.On(name, nil)
	if err != nil {
		t.Fatalf("read the configuration of %s: %v", name, err)
	}

	settings := map[string]string{}
	for _, entry := range resource.Configs {
		if entry.Value != nil {
			settings[entry.Key] = *entry.Value
		}
	}
	return int32(len(detail.Partitions)), settings
}

func createTopic(t *testing.T, addresses []string, name string, partitions int32, retention string) {
	t.Helper()

	admin := administrator(t, addresses)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := admin.CreateTopics(ctx, partitions, 1,
		map[string]*string{"retention.ms": kadm.StringPtr(retention)}, name); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
}

func TestTheMigratorCreatesTheDeclaredTopologyAndThenChangesNothing(t *testing.T) {
	addresses := brokers(t)
	topic := declaredTopic(t, addresses, 6, 48*time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	changed, err := provisioner(t, addresses).Apply(ctx, []broker.Topic{topic})
	if err != nil {
		t.Fatalf("apply the topology: %v", err)
	}
	if len(changed) != 1 || !strings.Contains(changed[0], "created "+topic.Name) {
		t.Fatalf("the first run reported %v", changed)
	}

	partitions, settings := shapeOf(t, addresses, topic.Name)
	if partitions != 6 {
		t.Errorf("%s was created with %d partitions, want 6", topic.Name, partitions)
	}
	if settings["retention.ms"] != "172800000" {
		t.Errorf("retention.ms is %q, want 172800000", settings["retention.ms"])
	}
	if settings["cleanup.policy"] != "delete" || settings["compression.type"] != "zstd" {
		t.Errorf("cleanup is %q and compression is %q", settings["cleanup.policy"], settings["compression.type"])
	}

	repeated, err := provisioner(t, addresses).Apply(ctx, []broker.Topic{topic})
	if err != nil {
		t.Fatalf("apply the topology a second time: %v", err)
	}
	if len(repeated) != 0 {
		t.Fatalf("a converged backbone reported %v as changed", repeated)
	}
}

func TestTheMigratorConvergesRetentionThatDriftedAwayFromTheTopology(t *testing.T) {
	addresses := brokers(t)
	topic := declaredTopic(t, addresses, 4, 48*time.Hour)
	createTopic(t, addresses, topic.Name, 4, "3600000")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	changed, err := provisioner(t, addresses).Apply(ctx, []broker.Topic{topic})
	if err != nil {
		t.Fatalf("apply the topology: %v", err)
	}
	if len(changed) == 0 {
		t.Fatal("a topic kept for one hour against a declaration of forty-eight reported no change")
	}

	_, settings := shapeOf(t, addresses, topic.Name)
	if settings["retention.ms"] != "172800000" {
		t.Fatalf("retention.ms stayed at %q", settings["retention.ms"])
	}
}

// Growing the partition count moves an agent's records to a different partition
// and ends the per-agent ordering, so the migrator reports it instead.
func TestTheMigratorRefusesToRepartitionAnExistingTopic(t *testing.T) {
	addresses := brokers(t)
	topic := declaredTopic(t, addresses, 6, 48*time.Hour)
	createTopic(t, addresses, topic.Name, 3, "172800000")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err := provisioner(t, addresses).Apply(ctx, []broker.Topic{topic})
	if err == nil {
		t.Fatal("a topic with three partitions was adopted by a topology declaring six")
	}
	if !strings.Contains(err.Error(), "ordering") {
		t.Errorf("the refusal does not say what is at stake: %v", err)
	}

	if partitions, _ := shapeOf(t, addresses, topic.Name); partitions != 3 {
		t.Fatalf("the refused run left %s with %d partitions", topic.Name, partitions)
	}
}

func TestAGatewayRefusesToServeWithoutTheTopicItPublishesTo(t *testing.T) {
	addresses := brokers(t)
	topic := declaredTopic(t, addresses, 6, 48*time.Hour)

	publisher, err := broker.NewPublisher(broker.Config{
		Brokers: addresses, Topic: topic.Name, ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if _, err := publisher.VerifyTopics(ctx, topic); err == nil {
		t.Fatal("a missing topic passed verification, so the gateway would report itself healthy and fail every batch")
	} else if !strings.Contains(err.Error(), "backbone-migrator") {
		t.Errorf("the refusal does not say how to fix it: %v", err)
	}

	if _, err := provisioner(t, addresses).Apply(ctx, []broker.Topic{topic}); err != nil {
		t.Fatalf("apply the topology: %v", err)
	}

	drift, err := publisher.VerifyTopics(ctx, topic)
	if err != nil {
		t.Fatalf("a provisioned topic failed verification: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("a freshly provisioned topic reported drift: %v", drift)
	}
}

// Retention drift is reported and not fatal: refusing to admit telemetry over a
// setting the process cannot fix would trade the stream for the window.
func TestVerificationReportsRetentionDriftWithoutRefusingToServe(t *testing.T) {
	addresses := brokers(t)
	topic := declaredTopic(t, addresses, 4, 48*time.Hour)
	createTopic(t, addresses, topic.Name, 4, "3600000")

	publisher, err := broker.NewPublisher(broker.Config{
		Brokers: addresses, Topic: topic.Name, ClientID: "integration-test",
	})
	if err != nil {
		t.Fatalf("build publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	drift, err := publisher.VerifyTopics(ctx, topic)
	if err != nil {
		t.Fatalf("retention drift stopped the process: %v", err)
	}
	if !slices.ContainsFunc(drift, func(entry string) bool {
		return strings.Contains(entry, "retention.ms") && strings.Contains(entry, "3600000")
	}) {
		t.Fatalf("the drift was reported as %v", drift)
	}
}
