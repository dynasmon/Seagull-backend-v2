//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

const failedRule = `schema_version: 1
rules:
  - id: authentication.failed
    revision: 1
    name: An authentication failed
    description: A rule narrow enough to be decided from one event.
    class: authentication
    severity: high
    status: active
    match:
      field: authentication.outcome
      equals: failure
`

const succeededRule = `schema_version: 1
rules:
  - id: authentication.succeeded
    revision: 1
    name: An authentication succeeded
    description: A second rule, so a second version differs from the first.
    class: authentication
    severity: low
    status: active
    match:
      field: authentication.outcome
      equals: success
`

func compactedTopic(t *testing.T, addresses []string) string {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	t.Cleanup(client.Close)

	admin := kadm.NewClient(client)
	topic := fmt.Sprintf("security.rulesets.test.%d", time.Now().UnixNano())
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

func publishedFrom(t *testing.T, document, by string) *ruleset.Version {
	t.Helper()

	read, err := rulefile.Parse("published.yml", []byte(document))
	if err != nil {
		t.Fatalf("read a rule: %v", err)
	}

	programs := make([]*detection.Program, 0, len(read))
	cases := make(map[detection.ID][]detection.Case, len(read))
	for _, rule := range read {
		programs = append(programs, rule.Program)
		if len(rule.Cases) > 0 {
			cases[rule.Program.Rule().ID] = rule.Cases
		}
	}

	version, err := ruleset.NewVersion(programs, cases, by, time.Now().UTC(), "")
	if err != nil {
		t.Fatalf("publish a version: %v", err)
	}
	return version
}

func replayed(t *testing.T, addresses []string, topic string) *ruleset.Catalogue {
	t.Helper()

	reader, err := broker.NewRulesetLog(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"}, 64)
	if err != nil {
		t.Fatalf("build a ruleset reader: %v", err)
	}
	t.Cleanup(reader.Close)

	catalogue := ruleset.NewCatalogue()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = reader.Replay(ctx, func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			if err := catalogue.Read(record.Value); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("replay the ruleset log: %v", err)
	}
	return catalogue
}

// A ruleset published on one process is the ruleset a second one composes,
// without either of them naming the other. This is the whole of BE-029's
// propagation: the control plane writes, the engine reads, and what the engine
// pins is what somebody approved.
func TestAPublishedRulesetReachesAProcessThatWasNotRunning(t *testing.T) {
	addresses := brokers(t)
	topic := compactedTopic(t, addresses)

	publisher, err := broker.NewRulesets(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build a ruleset publisher: %v", err)
	}
	defer publisher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first := publishedFrom(t, failedRule, "dev-engineer")
	second := publishedFrom(t, succeededRule, "dev-engineer")
	for _, version := range []*ruleset.Version{first, second} {
		if err := publisher.Publish(ctx, version.Record()); err != nil {
			t.Fatalf("publish %s: %v", version.ID(), err)
		}
	}
	if err := publisher.Publish(ctx, activated(string(second.ID()), "dev-admin")); err != nil {
		t.Fatalf("activate: %v", err)
	}

	catalogue := replayed(t, addresses, topic)
	if catalogue.Count() != 2 {
		t.Fatalf("a process replaying the log holds %d versions", catalogue.Count())
	}

	active, running := catalogue.Active()
	if !running {
		t.Fatal("a process replaying the log runs nothing")
	}
	if active.ID() != second.ID() {
		t.Fatalf("the log says run %s and the process pinned %s", second.ID(), active.ID())
	}
	if active.Snapshot().Running() != second.Snapshot().Running() {
		t.Errorf("%d rules run of %d", active.Snapshot().Running(), second.Snapshot().Running())
	}
	if active.PublishedBy() != "dev-engineer" {
		t.Errorf("the version crossed attributed to %q", active.PublishedBy())
	}
}

// Rolling back is a pointer at a version that is still on the log, so what
// comes back is what ran before rather than a rebuild of it.
func TestRollingBackReachesTheRulesetThatRanBefore(t *testing.T) {
	addresses := brokers(t)
	topic := compactedTopic(t, addresses)

	publisher, err := broker.NewRulesets(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build a ruleset publisher: %v", err)
	}
	defer publisher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first := publishedFrom(t, failedRule, "dev-engineer")
	second := publishedFrom(t, succeededRule, "dev-engineer")
	for _, record := range []*rulesetv1.Record{
		first.Record(),
		second.Record(),
		activated(string(second.ID()), "dev-engineer"),
		activated(string(first.ID()), "dev-admin"),
	} {
		if err := publisher.Publish(ctx, record); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}

	catalogue := replayed(t, addresses, topic)
	active, running := catalogue.Active()
	if !running || active.ID() != first.ID() {
		t.Fatalf("the rollback landed on %v", active)
	}
	if catalogue.Count() != 2 {
		t.Errorf("rolling back changed what is on the log: %d versions", catalogue.Count())
	}
	if catalogue.Activation().GetActivatedBy() != "dev-admin" {
		t.Errorf("the rollback was attributed to %q", catalogue.Activation().GetActivatedBy())
	}
}

// A process that starts after everything was published reads the whole log
// before it serves, so it never answers about half an estate.
func TestAFollowerSeesARulesetPublishedAfterItStarted(t *testing.T) {
	addresses := brokers(t)
	topic := compactedTopic(t, addresses)

	publisher, err := broker.NewRulesets(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build a ruleset publisher: %v", err)
	}
	defer publisher.Close()

	reader, err := broker.NewRulesetLog(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"}, 64)
	if err != nil {
		t.Fatalf("build a ruleset reader: %v", err)
	}
	defer reader.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := reader.Replay(ctx, func(context.Context, []broker.Record) error { return nil }); err != nil {
		t.Fatalf("replay an empty log: %v", err)
	}

	version := publishedFrom(t, failedRule, "dev-engineer")
	if err := publisher.Publish(ctx, version.Record()); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := publisher.Publish(ctx, activated(string(version.ID()), "dev-engineer")); err != nil {
		t.Fatalf("activate: %v", err)
	}

	catalogue := ruleset.NewCatalogue()
	pinned := make(chan struct{})
	follow, stop := context.WithCancel(ctx)
	defer stop()

	go func() {
		_ = reader.Follow(follow, func(_ context.Context, records []broker.Record) error {
			for _, record := range records {
				if err := catalogue.Read(record.Value); err != nil {
					return err
				}
			}
			if _, running := catalogue.Active(); running {
				select {
				case pinned <- struct{}{}:
				default:
				}
			}
			return nil
		})
	}()

	select {
	case <-pinned:
	case <-ctx.Done():
		t.Fatal("a follower never saw a ruleset published while it was running")
	}

	active, running := catalogue.Active()
	if !running || active.ID() != version.ID() {
		t.Fatalf("the follower pinned %v", active)
	}
}

func activated(id, by string) *rulesetv1.Record {
	return &rulesetv1.Record{Record: &rulesetv1.Record_Active{
		Active: &rulesetv1.Active{RulesetId: id, ActivatedBy: by},
	}}
}
