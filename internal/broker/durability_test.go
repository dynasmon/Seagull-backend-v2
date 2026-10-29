package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	platformmetrics "github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

func held(durability Durability, replicas, inSync int16) Topic {
	return Topic{
		Name:            "security.events.raw",
		Partitions:      12,
		Replicas:        replicas,
		Retention:       time.Hour,
		Cleanup:         cleanupDelete,
		Compression:     compressionZstd,
		MinInSync:       inSync,
		Durability:      durability,
		MaxMessageBytes: 1 << 20,
	}
}

func TestADefaultBackboneKeepsThreeReplicasAndAcknowledgesOnTwo(t *testing.T) {
	for _, topic := range declared(t, map[string]string{}).Topics() {
		if topic.Replicas != 3 || topic.MinInSync != 2 || topic.Durability != Production {
			t.Errorf("%s keeps %d replicas, acknowledges on %d and is %s: a deployment that set nothing acknowledges a record one disk holds",
				topic.Name, topic.Replicas, topic.MinInSync, topic.Durability)
		}
		if err := topic.Validate(); err != nil {
			t.Errorf("the default %s is refused: %v", topic.Name, err)
		}
	}
}

func TestAProductionBackboneRefusesWhatTheLossOfOneBrokerWouldCost(t *testing.T) {
	for name, topic := range map[string]Topic{
		"one replica":                   held(Production, 1, 1),
		"two replicas":                  held(Production, 2, 2),
		"three replicas, one in sync":   held(Production, 3, 1),
		"five replicas, one in sync":    held(Production, 5, 1),
		"a durability it does not know": held(Durability(7), 1, 1),
	} {
		if err := topic.Validate(); !errors.Is(err, ErrBelowProductionDurability) {
			t.Errorf("a topic with %s was answered %v", name, err)
		}
	}

	for name, topic := range map[string]Topic{
		"two of three in sync":   held(Production, 3, 2),
		"three of three in sync": held(Production, 3, 3),
		"three of five in sync":  held(Production, 5, 3),
	} {
		if err := topic.Validate(); err != nil {
			t.Errorf("a production topic with %s was refused: %v", name, err)
		}
	}
}

func TestADevelopmentBackboneIsDeclaredRatherThanInherited(t *testing.T) {
	inherited := declared(t, map[string]string{
		"SEAGULL_BACKBONE_REPLICAS":            "1",
		"SEAGULL_BACKBONE_MIN_INSYNC_REPLICAS": "1",
	})
	for _, topic := range inherited.Topics() {
		if err := topic.Validate(); !errors.Is(err, ErrBelowProductionDurability) {
			t.Errorf("%s keeps one replica nobody declared and was answered %v", topic.Name, err)
		}
	}

	stated := declared(t, map[string]string{
		"SEAGULL_BACKBONE_REPLICAS":            "1",
		"SEAGULL_BACKBONE_MIN_INSYNC_REPLICAS": "1",
		"SEAGULL_BACKBONE_DURABILITY":          "development",
	})
	for _, topic := range stated.Topics() {
		if topic.Durability != Development {
			t.Errorf("%s is %s under a declared development backbone", topic.Name, topic.Durability)
		}
		if err := topic.Validate(); err != nil {
			t.Errorf("%s was refused under a declared development backbone: %v", topic.Name, err)
		}
	}
}

func TestADurabilityTheBackboneDoesNotKnowIsRefused(t *testing.T) {
	parser := config.New(func(key string) (string, bool) {
		if key == "SEAGULL_BACKBONE_DURABILITY" {
			return "relaxed", true
		}
		return "", false
	})

	LoadTopology(parser)

	if parser.Err() == nil {
		t.Error("a durability nobody defined was read as one")
	}
}

func TestTheMigratorRefusesAnUndeclaredDevelopmentBackboneBeforeReachingIt(t *testing.T) {
	provisioner, err := NewProvisioner([]string{"127.0.0.1:1"}, "durability-test", Security{})
	if err != nil {
		t.Fatalf("build the provisioner: %v", err)
	}
	t.Cleanup(provisioner.Close)

	reached, cancel := context.WithCancel(context.Background())
	cancel()
	changed, err := provisioner.Apply(reached, []Topic{held(Production, 3, 2), held(Production, 1, 1)})
	if !errors.Is(err, ErrBelowProductionDurability) {
		t.Fatalf("the migrator answered %v, so it asked the broker for a topic one disk would hold", err)
	}
	if len(changed) != 0 {
		t.Errorf("the migrator changed %v before refusing the topology", changed)
	}
}

func TestAnAcknowledgementIsHeldByTheFewerOfTheInSyncFloorAndAMajority(t *testing.T) {
	for _, topic := range []struct{ replicas, inSync, by int16 }{
		{replicas: 3, inSync: 2, by: 2},
		{replicas: 3, inSync: 3, by: 2},
		{replicas: 4, inSync: 4, by: 3},
		{replicas: 5, inSync: 2, by: 2},
		{replicas: 5, inSync: 3, by: 3},
		{replicas: 2, inSync: 2, by: 2},
		{replicas: 2, inSync: 1, by: 1},
		{replicas: 1, inSync: 1, by: 1},
	} {
		if by := held(Development, topic.replicas, topic.inSync).acknowledgedBy(); by != topic.by {
			t.Errorf("%d replicas with %d in sync acknowledge a record %d of them hold, and either broker guarantees only %d",
				topic.replicas, topic.inSync, by, topic.by)
		}
	}
}

type reported struct {
	Level        string `json:"level"`
	Message      string `json:"msg"`
	Durability   string `json:"durability"`
	Replicas     int    `json:"replicas"`
	InSync       int    `json:"min_in_sync_replicas"`
	Acknowledged int    `json:"acknowledged_by"`
}

func reportOf(t *testing.T, topics ...Topic) []reported {
	t.Helper()

	var written bytes.Buffer
	LogDurability(context.Background(), slog.New(slog.NewJSONHandler(&written, nil)), topics...)

	var lines []reported
	for _, line := range strings.Split(strings.TrimSpace(written.String()), "\n") {
		var entry reported
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("read %q: %v", line, err)
		}
		lines = append(lines, entry)
	}
	return lines
}

func TestABackboneAcknowledgingWhatOneReplicaHoldsIsAWarningAtStartup(t *testing.T) {
	lines := reportOf(t, held(Development, 1, 1), held(Development, 1, 1))

	want := reported{Level: "WARN", Message: "backbone_durability", Durability: "development", Replicas: 1, InSync: 1, Acknowledged: 1}
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("a development backbone was reported as %+v, want %+v once", lines, want)
	}
}

func TestAProductionBackboneIsReportedByTheTopicWhoseAcknowledgementIsWorthLeast(t *testing.T) {
	lines := reportOf(t, held(Production, 5, 3), held(Production, 3, 2), held(Production, 4, 3))

	want := reported{Level: "INFO", Message: "backbone_durability", Durability: "production", Replicas: 3, InSync: 2, Acknowledged: 2}
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("a production backbone was reported as %+v, want %+v once", lines, want)
	}
}

func TestTheReplicasBehindAnAcknowledgementAreAGauge(t *testing.T) {
	registry := platformmetrics.New("test")

	ObserveDurability(registry, held(Production, 5, 3), held(Production, 3, 2))

	if by := metricValue(t, registry, "seagull_backbone_acknowledging_replicas"); by != 2 {
		t.Fatalf("the gauge says an acknowledged record is held by %.0f replicas, and the weakest topic holds it on 2", by)
	}
}
