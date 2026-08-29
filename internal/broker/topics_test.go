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
	for _, topic := range topology.Topics() {
		if topic.Replicas != 3 {
			t.Errorf("%s is declared with %d replicas: the topology must not assume a single broker", topic.Name, topic.Replicas)
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
	}
	if err := complete.Validate(); err != nil {
		t.Fatalf("a complete topic was refused: %v", err)
	}

	for name, broken := range map[string]func(Topic) Topic{
		"no name":        func(topic Topic) Topic { topic.Name = ""; return topic },
		"no partition":   func(topic Topic) Topic { topic.Partitions = 0; return topic },
		"no replica":     func(topic Topic) Topic { topic.Replicas = 0; return topic },
		"no retention":   func(topic Topic) Topic { topic.Retention = 0; return topic },
		"no cleanup":     func(topic Topic) Topic { topic.Cleanup = ""; return topic },
		"no compression": func(topic Topic) Topic { topic.Compression = ""; return topic },
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
	if want := []string{retentionKey, cleanupKey, compressionKey}; !slices.Equal(keys, want) {
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
