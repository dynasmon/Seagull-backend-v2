package broker

import (
	"slices"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

func declared(t *testing.T, environment map[string]string) Topology {
	t.Helper()

	parser := config.New(func(key string) (string, bool) {
		value, found := environment[key]
		return value, found
	})
	topology := LoadTopology(parser)
	if err := parser.Err(); err != nil {
		t.Fatalf("load the topology: %v", err)
	}
	return topology
}

func TestTheDefaultTopologyIsTheOneTheBackboneNeeds(t *testing.T) {
	topology := declared(t, map[string]string{})

	if topology.Events.Name != "security.events.raw" {
		t.Errorf("events topic is %q", topology.Events.Name)
	}
	if topology.Quarantine.Name != "security.events.quarantine" {
		t.Errorf("quarantine topic is %q", topology.Quarantine.Name)
	}
	if topology.Events.Partitions <= topology.Quarantine.Partitions {
		t.Errorf("admitted telemetry spreads over %d partitions and refused records over %d",
			topology.Events.Partitions, topology.Quarantine.Partitions)
	}
	if topology.Quarantine.Retention <= topology.Events.Retention {
		t.Errorf("refused records are kept %s and admitted ones %s: a refused record is the one still waiting to be read",
			topology.Quarantine.Retention, topology.Events.Retention)
	}
	if topology.Detections.Name != "security.detections" {
		t.Errorf("detections topic is %q", topology.Detections.Name)
	}
	if topology.Detections.Partitions >= topology.Events.Partitions {
		t.Errorf("detections spread over %d partitions and the telemetry they are made from over %d",
			topology.Detections.Partitions, topology.Events.Partitions)
	}
	if topology.Detections.Retention <= topology.Events.Retention {
		t.Errorf("detections are kept %s and the events behind them %s: a detection is the one still waiting to be read",
			topology.Detections.Retention, topology.Events.Retention)
	}
	if topology.DetectionsQuarantine.Name != "security.detections.quarantine" {
		t.Errorf("the detection quarantine topic is %q", topology.DetectionsQuarantine.Name)
	}
	if topology.DetectionsQuarantine.Name == topology.Quarantine.Name {
		t.Error("both streams quarantine to one topic, and a refused record's offset only means something alongside its own topic")
	}
	if topology.Inventory.Name != "security.inventory.raw" {
		t.Errorf("inventory topic is %q", topology.Inventory.Name)
	}
	if topology.InventoryQuarantine.Name != "security.inventory.quarantine" {
		t.Errorf("the inventory quarantine topic is %q", topology.InventoryQuarantine.Name)
	}
	if topology.InventoryQuarantine.Name == topology.Quarantine.Name ||
		topology.InventoryQuarantine.Name == topology.DetectionsQuarantine.Name {
		t.Error("two streams quarantine to one topic, and a refused record's offset only means something alongside its own topic")
	}
	if topology.Inventory.Retention <= topology.Events.Retention {
		t.Errorf("inventory is kept %s and telemetry %s: the current state of an asset is rebuilt by replaying this topic",
			topology.Inventory.Retention, topology.Events.Retention)
	}
	for _, topic := range topology.Topics() {
		if err := topic.Validate(); err != nil {
			t.Errorf("the default topology is not valid: %v", err)
		}
	}
}

func TestEveryTopicPropertyIsConfigurablePerEnvironment(t *testing.T) {
	topology := declared(t, map[string]string{
		"SEAGULL_BACKBONE_EVENTS_TOPIC":                     "tenant.events",
		"SEAGULL_BACKBONE_EVENTS_PARTITIONS":                "24",
		"SEAGULL_BACKBONE_EVENTS_RETENTION":                 "48h",
		"SEAGULL_BACKBONE_QUARANTINE_TOPIC":                 "tenant.refused",
		"SEAGULL_BACKBONE_QUARANTINE_PARTITIONS":            "6",
		"SEAGULL_BACKBONE_QUARANTINE_RETENTION":             "72h",
		"SEAGULL_BACKBONE_DETECTIONS_TOPIC":                 "tenant.detections",
		"SEAGULL_BACKBONE_DETECTIONS_PARTITIONS":            "9",
		"SEAGULL_BACKBONE_DETECTIONS_RETENTION":             "96h",
		"SEAGULL_BACKBONE_DETECTIONS_QUARANTINE_TOPIC":      "tenant.detections.refused",
		"SEAGULL_BACKBONE_DETECTIONS_QUARANTINE_PARTITIONS": "2",
		"SEAGULL_BACKBONE_DETECTIONS_QUARANTINE_RETENTION":  "48h",
		"SEAGULL_BACKBONE_INVENTORY_TOPIC":                  "tenant.inventory",
		"SEAGULL_BACKBONE_INVENTORY_PARTITIONS":             "4",
		"SEAGULL_BACKBONE_INVENTORY_RETENTION":              "240h",
		"SEAGULL_BACKBONE_INVENTORY_QUARANTINE_TOPIC":       "tenant.inventory.refused",
		"SEAGULL_BACKBONE_INVENTORY_QUARANTINE_PARTITIONS":  "5",
		"SEAGULL_BACKBONE_INVENTORY_QUARANTINE_RETENTION":   "120h",
		"SEAGULL_BACKBONE_REPLICAS":                         "3",
	})

	if topology.Events.Partitions != 24 || topology.Events.Retention != 48*time.Hour {
		t.Errorf("events read back as %d partitions and %s", topology.Events.Partitions, topology.Events.Retention)
	}
	if topology.Quarantine.Partitions != 6 || topology.Quarantine.Retention != 72*time.Hour {
		t.Errorf("quarantine read back as %d partitions and %s", topology.Quarantine.Partitions, topology.Quarantine.Retention)
	}
	if topology.Detections.Partitions != 9 || topology.Detections.Retention != 96*time.Hour {
		t.Errorf("detections read back as %d partitions and %s", topology.Detections.Partitions, topology.Detections.Retention)
	}
	if topology.DetectionsQuarantine.Partitions != 2 || topology.DetectionsQuarantine.Retention != 48*time.Hour {
		t.Errorf("the detection quarantine read back as %d partitions and %s",
			topology.DetectionsQuarantine.Partitions, topology.DetectionsQuarantine.Retention)
	}
	if topology.Inventory.Name != "tenant.inventory" || topology.Inventory.Partitions != 4 || topology.Inventory.Retention != 240*time.Hour {
		t.Errorf("inventory read back as %q over %d partitions and %s",
			topology.Inventory.Name, topology.Inventory.Partitions, topology.Inventory.Retention)
	}
	if topology.InventoryQuarantine.Partitions != 5 || topology.InventoryQuarantine.Retention != 120*time.Hour {
		t.Errorf("the inventory quarantine read back as %d partitions and %s",
			topology.InventoryQuarantine.Partitions, topology.InventoryQuarantine.Retention)
	}
	for _, topic := range topology.Topics() {
		if topic.Replicas != 3 {
			t.Errorf("%s is declared with %d replicas: the topology must not assume a single broker", topic.Name, topic.Replicas)
		}
		if topic.MinInSync != 2 {
			t.Errorf("%s acknowledges a write on %d of 3 replicas: acks from every in-sync replica means nothing when one of them is in sync",
				topic.Name, topic.MinInSync)
		}
	}
}

func TestAnIncompleteTopicIsRefused(t *testing.T) {
	complete := Topic{
		Name:        "security.events.raw",
		Partitions:  12,
		Replicas:    1,
		Retention:   time.Hour,
		Cleanup:     cleanupDelete,
		Compression: compressionZstd,
		MinInSync:   1,
	}
	if err := complete.Validate(); err != nil {
		t.Fatalf("a complete topic was refused: %v", err)
	}

	for name, broken := range map[string]func(Topic) Topic{
		"no name":            func(topic Topic) Topic { topic.Name = ""; return topic },
		"no partition":       func(topic Topic) Topic { topic.Partitions = 0; return topic },
		"no replica":         func(topic Topic) Topic { topic.Replicas = 0; return topic },
		"no retention":       func(topic Topic) Topic { topic.Retention = 0; return topic },
		"no cleanup":         func(topic Topic) Topic { topic.Cleanup = ""; return topic },
		"no compression":     func(topic Topic) Topic { topic.Compression = ""; return topic },
		"no in-sync replica": func(topic Topic) Topic { topic.MinInSync = 0; return topic },
		"more in-sync replicas than replicas": func(topic Topic) Topic {
			topic.Replicas, topic.MinInSync = 2, 3
			return topic
		},
	} {
		if err := broken(complete).Validate(); err == nil {
			t.Errorf("a topic with %s was accepted", name)
		}
	}
}

// The migrator reports what it changed, so the same divergence has to be
// described in the same order on every run.
func TestTheSettingsOfATopicAreOrdered(t *testing.T) {
	topic := declared(t, map[string]string{}).Events

	var keys []string
	for _, entry := range topic.settings() {
		keys = append(keys, entry.key)
	}
	if want := []string{retentionKey, cleanupKey, compressionKey, minInSyncKey}; !slices.Equal(keys, want) {
		t.Fatalf("settings are ordered %v, want %v", keys, want)
	}

	for range 20 {
		var repeated []string
		for _, entry := range topic.settings() {
			repeated = append(repeated, entry.key)
		}
		if !slices.Equal(repeated, keys) {
			t.Fatalf("settings came back ordered %v and then %v", keys, repeated)
		}
	}
}

func TestRetentionReachesTheBrokerAsMilliseconds(t *testing.T) {
	topic := declared(t, map[string]string{"SEAGULL_BACKBONE_EVENTS_RETENTION": "168h"}).Events

	for _, entry := range topic.settings() {
		if entry.key != retentionKey {
			continue
		}
		if entry.value != "604800000" {
			t.Fatalf("168h reaches the broker as %q", entry.value)
		}
		return
	}
	t.Fatal("the settings carry no retention")
}

func TestAReshapedTopicIsRefusedRatherThanAdopted(t *testing.T) {
	declaration := Topic{Name: "security.events.raw", Partitions: 12, Replicas: 1}

	if err := shapeAgrees(declaration, detailOf(12, 1)); err != nil {
		t.Fatalf("the declared shape was refused: %v", err)
	}
	if err := shapeAgrees(declaration, detailOf(1, 1)); err == nil {
		t.Error("a topic auto-created with one partition was accepted")
	}
	if err := shapeAgrees(declaration, detailOf(24, 1)); err == nil {
		t.Error("a topic that grew to 24 partitions was accepted, which moves agents between partitions")
	}
	if err := shapeAgrees(declaration, detailOf(12, 3)); err == nil {
		t.Error("a topic replicated three times was accepted against a declaration of one")
	}
}

func detailOf(partitions int32, replicas int) kadm.TopicDetail {
	details := make(kadm.PartitionDetails, partitions)
	for partition := range partitions {
		brokers := make([]int32, replicas)
		for replica := range replicas {
			brokers[replica] = int32(replica)
		}
		details[partition] = kadm.PartitionDetail{Partition: partition, Replicas: brokers}
	}
	return kadm.TopicDetail{Topic: "security.events.raw", Partitions: details}
}

// A ruleset is kept for as long as the platform runs, because a detection made
// six months ago names the ruleset that decided it and an operator has to be
// able to read that ruleset back.
func TestTheRulesetTopicIsCompactedAndKeepsEveryVersion(t *testing.T) {
	topology := declared(t, map[string]string{})

	if topology.Rulesets.Name != "security.rulesets" {
		t.Errorf("rulesets topic is %q", topology.Rulesets.Name)
	}
	if topology.Rulesets.Cleanup != cleanupCompact {
		t.Errorf("the ruleset topic is cleaned up by %q", topology.Rulesets.Cleanup)
	}
	if topology.Rulesets.Retention != 0 {
		t.Errorf("a compacted topic declared a retention of %s", topology.Rulesets.Retention)
	}
	if err := topology.Rulesets.Validate(); err != nil {
		t.Errorf("the shipped ruleset topic is refused: %v", err)
	}
	if !slices.ContainsFunc(topology.Topics(), func(topic Topic) bool { return topic.Name == topology.Rulesets.Name }) {
		t.Error("the ruleset topic is not in the topology the migrator applies")
	}

	for _, entry := range topology.Rulesets.settings() {
		if entry.key == retentionKey && entry.value != "-1" {
			t.Errorf("a compacted topic asks for retention.ms=%s", entry.value)
		}
	}
}

// One partition, so that a published ruleset and the record activating it are
// read in the order they were written. A second one would let an engine see the
// pointer before the ruleset it names.
func TestTheRulesetTopicHasOnePartitionAndItIsNotASetting(t *testing.T) {
	topology := declared(t, map[string]string{"SEAGULL_BACKBONE_RULESETS_PARTITIONS": "12"})

	if topology.Rulesets.Partitions != 1 {
		t.Errorf("the ruleset topic spreads over %d partitions", topology.Rulesets.Partitions)
	}
}

func TestATopicThatDeletesStillNeedsARetention(t *testing.T) {
	topic := Topic{Name: "security.events.raw", Partitions: 1, Replicas: 1, Cleanup: cleanupDelete, Compression: compressionZstd}

	if err := topic.Validate(); err == nil {
		t.Error("a topic that deletes was accepted without a retention")
	}

	topic.Cleanup, topic.Retention = cleanupCompact, time.Hour
	if err := topic.Validate(); err == nil {
		t.Error("a compacted topic was accepted with a retention that will never apply")
	}
}

// Retention and compression cost a window or some disk, and a process that
// refused to serve over one would trade the stream for the setting.
func TestOperationalDifferencesAreReportedAndNotFatal(t *testing.T) {
	for _, held := range []difference{
		{key: retentionKey, held: "3600000", declared: "172800000", contract: operational},
		{key: compressionKey, held: "producer", declared: compressionZstd, contract: operational},
	} {
		if held.breaks() {
			t.Errorf("%s stopped a process from serving", held.key)
		}
	}
}

// A compacted topic turned to delete drops the registry every reader replays,
// and a deleted one turned to compact keeps one record per key of a stream that
// was never keyed for it. Neither is a window somebody can wait out.
func TestACleanupPolicyThatDisagreesBreaksTheTopology(t *testing.T) {
	held := difference{key: cleanupKey, held: cleanupDelete, declared: cleanupCompact, contract: exact}
	if !held.breaks() {
		t.Error("a compacted topic serving as a deleted one was reported as drift")
	}
}

// Fewer in-sync replicas than were declared makes `acks=all` acknowledge a write
// that is not durable, which is a wrong answer rather than a degraded one.
func TestFewerInSyncReplicasThanDeclaredBreaksTheTopology(t *testing.T) {
	held := difference{key: minInSyncKey, held: "1", declared: "2", contract: atLeast}
	if !held.breaks() {
		t.Error("a reduced durability floor was reported as drift")
	}

	stricter := difference{key: minInSyncKey, held: "3", declared: "2", contract: atLeast}
	if stricter.breaks() {
		t.Error("a stricter durability floor stopped a process from serving")
	}
}

func TestAnUnboundedValueIsNeverShortOfWhatWasDeclared(t *testing.T) {
	if shortOf("-1", "172800000") {
		t.Error("unbounded retention was read as shorter than two days")
	}
	if !shortOf("172800000", "-1") {
		t.Error("two days was read as long as unbounded retention")
	}
	if shortOf("producer", cleanupCompact) {
		t.Error("two words that are not numbers were compared as numbers")
	}
}

// Every setting the topology declares is classified, so a setting added
// tomorrow is judged deliberately rather than by whichever value iota gave it.
func TestEverySettingDeclaresWhatADifferenceMeans(t *testing.T) {
	wanted := map[string]agreement{
		retentionKey:   operational,
		cleanupKey:     exact,
		compressionKey: operational,
		minInSyncKey:   atLeast,
	}

	topic := Topic{Name: "t", Partitions: 1, Replicas: 1, Retention: 0, Cleanup: cleanupCompact, Compression: compressionZstd, MinInSync: 1}
	held := topic.settings()
	if len(held) != len(wanted) {
		t.Fatalf("a topic declares %d settings and %d are classified", len(held), len(wanted))
	}
	for _, entry := range held {
		if entry.contract != wanted[entry.key] {
			t.Errorf("%s is classified %d", entry.key, entry.contract)
		}
	}
}

func TestInventoryIsAStreamOfItsOwnAndTheMigratorCreatesIt(t *testing.T) {
	topology := declared(t, map[string]string{})

	if topology.Inventory.Name == topology.Events.Name {
		t.Error("inventory and telemetry share a topic")
	}
	if topology.Inventory.Cleanup != cleanupDelete {
		t.Errorf("the inventory topic is cleaned up by %q, and a record of what was seen is not superseded by key", topology.Inventory.Cleanup)
	}
	if err := topology.Inventory.Validate(); err != nil {
		t.Errorf("the shipped inventory topic is refused: %v", err)
	}
	for _, topic := range []Topic{topology.Inventory, topology.InventoryQuarantine} {
		if !slices.ContainsFunc(topology.Topics(), func(applied Topic) bool { return applied.Name == topic.Name }) {
			t.Errorf("%s is not in the topology the migrator applies, so the processes that need it would refuse to serve", topic.Name)
		}
	}
}
