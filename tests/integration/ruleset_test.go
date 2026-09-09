//go:build integration

package integration_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/types/known/timestamppb"

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

	reader, err := broker.NewStateLog(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"}, 64)
	if err != nil {
		t.Fatalf("build a ruleset reader: %v", err)
	}
	t.Cleanup(reader.Close)

	catalogue := ruleset.NewCatalogue()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = reader.Replay(ctx, func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			if err := catalogue.Read(record.Value, broker.Desired(record.Key)); err != nil {
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
	activate(t, ctx, publisher, string(second.ID()), "dev-admin")

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
	for _, version := range []*ruleset.Version{first, second} {
		if err := publisher.Publish(ctx, version.Record()); err != nil {
			t.Fatalf("publish %s: %v", version.ID(), err)
		}
	}
	activate(t, ctx, publisher, string(second.ID()), "dev-engineer")
	activate(t, ctx, publisher, string(first.ID()), "dev-admin")

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

	reader, err := broker.NewStateLog(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"}, 64)
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
	activate(t, ctx, publisher, string(version.ID()), "dev-engineer")

	catalogue := ruleset.NewCatalogue()
	pinned := make(chan struct{})
	follow, stop := context.WithCancel(ctx)
	defer stop()

	go func() {
		_ = reader.Follow(follow, func(_ context.Context, records []broker.Record) error {
			for _, record := range records {
				if err := catalogue.Read(record.Value, broker.Desired(record.Key)); err != nil {
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

func activate(t *testing.T, ctx context.Context, publisher *broker.Rulesets, id, by string) {
	t.Helper()

	active := &rulesetv1.Active{RulesetId: id, ActivatedBy: by, ActivatedAt: timestamppb.New(time.Now().UTC())}
	if err := publisher.Activate(ctx, ruleset.ActivationKey(active), active); err != nil {
		t.Fatalf("activate %s: %v", id, err)
	}
}

const rewrittenRule = `schema_version: 1
rules:
  - id: authentication.failed
    revision: 1
    name: An authentication failed
    description: A rule narrow enough to be decided from one event.
    class: authentication
    severity: critical
    status: active
    match:
      field: authentication.outcome
      equals: failure
`

// A detection is named by the rule and the revision that decided it, and so is
// the state a counting rule remembers. A second version reusing the pair for
// another question is refused by every process that reads the log, so it never
// becomes what an engine runs however it reached the topic — and the version
// that was already published stays readable and still activates.
func TestARevisionRepublishedAskingSomethingElseIsRefusedByEveryReader(t *testing.T) {
	addresses := brokers(t)
	topic := compactedTopic(t, addresses)

	publisher, err := broker.NewRulesets(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build a ruleset publisher: %v", err)
	}
	defer publisher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	published := publishedFrom(t, failedRule, "dev-engineer")
	rewritten := publishedFrom(t, rewrittenRule, "dev-engineer")
	if published.ID() == rewritten.ID() {
		t.Fatal("the two versions are the same ruleset, so nothing is being tested")
	}

	for _, version := range []*ruleset.Version{published, rewritten} {
		if err := publisher.Publish(ctx, version.Record()); err != nil {
			t.Fatalf("publish %s: %v", version.ID(), err)
		}
	}
	activate(t, ctx, publisher, string(rewritten.ID()), "dev-engineer")

	catalogue := ruleset.NewCatalogue()
	reader, err := broker.NewStateLog(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"}, 64)
	if err != nil {
		t.Fatalf("build a ruleset reader: %v", err)
	}
	t.Cleanup(reader.Close)

	var refused []error
	replayCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	err = reader.Replay(replayCtx, func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			if err := catalogue.Read(record.Value, broker.Desired(record.Key)); err != nil {
				refused = append(refused, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("replay the ruleset log: %v", err)
	}

	if len(refused) != 1 {
		t.Fatalf("the reader refused %d records: %v", len(refused), refused)
	}
	var conflict *ruleset.Conflict
	if !errors.As(refused[0], &conflict) {
		t.Fatalf("the refusal is not a revision conflict: %v", refused[0])
	}

	if !catalogue.Published(published.ID()) {
		t.Error("the version that was published first is no longer readable")
	}
	if catalogue.Published(rewritten.ID()) {
		t.Error("the rewritten version reached the catalogue")
	}
	if _, running := catalogue.Active(); running {
		t.Error("a pointer at a refused version named something to run")
	}
}

// The topic keeps one pointer and one line per activation, and compaction is
// what makes that true: the key the pointer is written under is written again on
// every activation, and no line of the trail is ever written twice. A reader
// that replays the log holds the ruleset to run now and every activation that
// led to it, including the ones whose pointers compaction has already dropped.
func TestTheActivationTrailOutlivesThePointersItReplaced(t *testing.T) {
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

	rollout := []struct{ id, by, note string }{
		{string(first.ID()), "dev-engineer", "first rollout"},
		{string(second.ID()), "dev-admin", "second rollout"},
		{string(first.ID()), "dev-admin", "rolled back"},
	}
	for _, rolled := range rollout {
		active := &rulesetv1.Active{
			RulesetId:   rolled.id,
			ActivatedBy: rolled.by,
			ActivatedAt: timestamppb.New(time.Now().UTC()),
			Note:        rolled.note,
		}
		if err := publisher.Activate(ctx, ruleset.ActivationKey(active), active); err != nil {
			t.Fatalf("activate %s: %v", rolled.id, err)
		}
	}

	catalogue := replayed(t, addresses, topic)

	active, running := catalogue.Active()
	if !running || active.ID() != first.ID() {
		t.Fatalf("the pointer names %v and the last activation named %s", active, first.ID())
	}

	trail := catalogue.Activations()
	if len(trail) != len(rollout) {
		t.Fatalf("the trail holds %d activations and %d happened", len(trail), len(rollout))
	}
	for index, rolled := range rollout {
		if trail[index].GetRulesetId() != rolled.id ||
			trail[index].GetActivatedBy() != rolled.by ||
			trail[index].GetNote() != rolled.note {
			t.Errorf("line %d of the trail reads %v", index, trail[index])
		}
		if trail[index].GetActivatedAt().AsTime().IsZero() {
			t.Errorf("line %d of the trail says nothing about when it happened", index)
		}
	}
}

// An activation republished by a retry is one thing that happened, so it is one
// line of the trail rather than two.
func TestAnActivationPublishedTwiceIsOneLineOfTheTrail(t *testing.T) {
	addresses := brokers(t)
	topic := compactedTopic(t, addresses)

	publisher, err := broker.NewRulesets(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build a ruleset publisher: %v", err)
	}
	defer publisher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	version := publishedFrom(t, failedRule, "dev-engineer")
	if err := publisher.Publish(ctx, version.Record()); err != nil {
		t.Fatalf("publish: %v", err)
	}

	active := &rulesetv1.Active{
		RulesetId:   string(version.ID()),
		ActivatedBy: "dev-engineer",
		ActivatedAt: timestamppb.New(time.Now().UTC()),
		Note:        "published twice by a retry",
	}
	for range 2 {
		if err := publisher.Activate(ctx, ruleset.ActivationKey(active), active); err != nil {
			t.Fatalf("activate: %v", err)
		}
	}

	catalogue := replayed(t, addresses, topic)
	if trail := catalogue.Activations(); len(trail) != 1 {
		t.Fatalf("one activation published twice left %d lines of the trail", len(trail))
	}
	if _, running := catalogue.Active(); !running {
		t.Error("the pointer was lost")
	}
}
