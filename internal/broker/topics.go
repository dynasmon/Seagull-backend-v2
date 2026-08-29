package broker

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

const (
	retentionKey   = "retention.ms"
	cleanupKey     = "cleanup.policy"
	compressionKey = "compression.type"

	cleanupDelete   = "delete"
	cleanupCompact  = "compact"
	compressionZstd = "zstd"
)

type Topic struct {
	Name        string
	Partitions  int32
	Replicas    int16
	Retention   time.Duration
	Cleanup     string
	Compression string
}

type Topology struct {
	Events               Topic
	Quarantine           Topic
	Detections           Topic
	DetectionsQuarantine Topic
	Rulesets             Topic
}

// Refused records and detections are both kept far longer than admitted events:
// an admitted event is already in the store, and the other two are still waiting
// for something to pick them up. Detections are rarer than the telemetry they
// are made from, so the topic carrying them is narrower than the one it reads.
func LoadTopology(parser *config.Parser) Topology {
	replicas := int16(parser.Int("SEAGULL_BACKBONE_REPLICAS", 1, 1, 15))
	return Topology{
		Events: Topic{
			Name:        parser.String("SEAGULL_BACKBONE_EVENTS_TOPIC", "security.events.raw"),
			Partitions:  int32(parser.Int("SEAGULL_BACKBONE_EVENTS_PARTITIONS", 12, 1, 1_000)),
			Replicas:    replicas,
			Retention:   parser.Duration("SEAGULL_BACKBONE_EVENTS_RETENTION", 7*24*time.Hour, time.Hour, 10*365*24*time.Hour),
			Cleanup:     cleanupDelete,
			Compression: compressionZstd,
		},
		Quarantine: Topic{
			Name:        parser.String("SEAGULL_BACKBONE_QUARANTINE_TOPIC", "security.events.quarantine"),
			Partitions:  int32(parser.Int("SEAGULL_BACKBONE_QUARANTINE_PARTITIONS", 3, 1, 1_000)),
			Replicas:    replicas,
			Retention:   parser.Duration("SEAGULL_BACKBONE_QUARANTINE_RETENTION", 30*24*time.Hour, time.Hour, 10*365*24*time.Hour),
			Cleanup:     cleanupDelete,
			Compression: compressionZstd,
		},
		Detections: Topic{
			Name:        parser.String("SEAGULL_BACKBONE_DETECTIONS_TOPIC", "security.detections"),
			Partitions:  int32(parser.Int("SEAGULL_BACKBONE_DETECTIONS_PARTITIONS", 6, 1, 1_000)),
			Replicas:    replicas,
			Retention:   parser.Duration("SEAGULL_BACKBONE_DETECTIONS_RETENTION", 30*24*time.Hour, time.Hour, 10*365*24*time.Hour),
			Cleanup:     cleanupDelete,
			Compression: compressionZstd,
		},
		// One quarantine per stream, not one for the platform: a refused record
		// carries the partition and offset it came from, and those only mean
		// something alongside the topic they came from.
		DetectionsQuarantine: Topic{
			Name:        parser.String("SEAGULL_BACKBONE_DETECTIONS_QUARANTINE_TOPIC", "security.detections.quarantine"),
			Partitions:  int32(parser.Int("SEAGULL_BACKBONE_DETECTIONS_QUARANTINE_PARTITIONS", 3, 1, 1_000)),
			Replicas:    replicas,
			Retention:   parser.Duration("SEAGULL_BACKBONE_DETECTIONS_QUARANTINE_RETENTION", 30*24*time.Hour, time.Hour, 10*365*24*time.Hour),
			Cleanup:     cleanupDelete,
			Compression: compressionZstd,
		},
		Rulesets: Topic{
			Name:        parser.String("SEAGULL_BACKBONE_RULESETS_TOPIC", "security.rulesets"),
			Partitions:  1,
			Replicas:    replicas,
			Cleanup:     cleanupCompact,
			Compression: compressionZstd,
		},
	}
}

func (t Topology) Topics() []Topic {
	return []Topic{t.Events, t.Quarantine, t.Detections, t.DetectionsQuarantine, t.Rulesets}
}

func (t Topic) Validate() error {
	switch {
	case t.Name == "":
		return errors.New("a backbone topic needs a name")
	case t.Partitions < 1:
		return fmt.Errorf("%s needs at least one partition", t.Name)
	case t.Replicas < 1:
		return fmt.Errorf("%s needs at least one replica", t.Name)
	case t.Cleanup == "":
		return fmt.Errorf("%s needs a cleanup policy", t.Name)
	case t.Cleanup == cleanupDelete && t.Retention <= 0:
		return fmt.Errorf("%s needs a positive retention", t.Name)
	case t.Cleanup == cleanupCompact && t.Retention > 0:
		return fmt.Errorf("%s is compacted and keeps the latest of every key, so it declares no retention", t.Name)
	case t.Compression == "":
		return fmt.Errorf("%s needs a compression type", t.Name)
	}
	return nil
}

type setting struct{ key, value string }

func retentionOf(t Topic) string {
	if t.Retention <= 0 {
		return "-1"
	}
	return strconv.FormatInt(t.Retention.Milliseconds(), 10)
}

// Ordered, not a map: the migrator reports what it changed, and a run has to
// describe the same divergence in the same words every time.
func (t Topic) settings() []setting {
	return []setting{
		{key: retentionKey, value: retentionOf(t)},
		{key: cleanupKey, value: t.Cleanup},
		{key: compressionKey, value: t.Compression},
	}
}

type Provisioner struct {
	client *kgo.Client
	admin  *kadm.Client
}

func NewProvisioner(brokers []string, clientID string) (*Provisioner, error) {
	if len(brokers) == 0 {
		return nil, errors.New("the backbone needs at least one broker address")
	}
	client, err := kgo.NewClient(kgo.SeedBrokers(brokers...), kgo.ClientID(clientID))
	if err != nil {
		return nil, fmt.Errorf("create backbone admin client: %w", err)
	}
	return &Provisioner{client: client, admin: kadm.NewClient(client)}, nil
}

// Retention, cleanup and compression converge; partitions and replication are
// refused. Repartitioning moves an agent's records to a different partition and
// silently ends the per-agent ordering, so it is an operator's decision.
func (p *Provisioner) Apply(ctx context.Context, topics []Topic) ([]string, error) {
	var changed []string
	for _, topic := range topics {
		if err := topic.Validate(); err != nil {
			return changed, err
		}
	}

	for _, topic := range topics {
		detail, err := describe(ctx, p.admin, topic.Name)
		if err != nil {
			return changed, err
		}
		if detail == nil {
			created, err := create(ctx, p.admin, topic)
			if err != nil {
				return changed, err
			}
			if created {
				changed = append(changed, "created "+topic.Name)
				continue
			}
			if detail, err = describe(ctx, p.admin, topic.Name); err != nil || detail == nil {
				return changed, fmt.Errorf("%s was created by another run and cannot be read back", topic.Name)
			}
		}
		if err := shapeAgrees(topic, *detail); err != nil {
			return changed, err
		}
		converged, err := converge(ctx, p.admin, topic)
		if err != nil {
			return changed, err
		}
		changed = append(changed, converged...)
	}
	return changed, nil
}

func (p *Provisioner) Ping(ctx context.Context) error {
	if err := p.client.Ping(ctx); err != nil {
		return fmt.Errorf("reach the backbone: %w", err)
	}
	return nil
}

func (p *Provisioner) Close() { p.client.Close() }

func (p *Publisher) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(p.client), topics)
}

func (c *Consumer) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(c.client), topics)
}

func (d *Detections) VerifyTopics(ctx context.Context, topics ...Topic) ([]string, error) {
	return verifyTopics(ctx, kadm.NewClient(d.client), topics)
}

// Readiness reaches the brokers, not the topics. A missing topic surfaces only
// when an agent's first batch fails, and a reshaped one never surfaces at all:
// one partition instead of twelve works, and only ends per-agent ordering.
func verifyTopics(ctx context.Context, admin *kadm.Client, topics []Topic) ([]string, error) {
	var drift []string
	for _, topic := range topics {
		if err := topic.Validate(); err != nil {
			return nil, err
		}
		detail, err := describe(ctx, admin, topic.Name)
		if err != nil {
			return nil, err
		}
		if detail == nil {
			return nil, fmt.Errorf("the backbone has no topic %s — run backbone-migrator", topic.Name)
		}
		if err := shapeAgrees(topic, *detail); err != nil {
			return nil, err
		}
		diverged, err := diverging(ctx, admin, topic)
		if err != nil {
			return nil, err
		}
		drift = append(drift, diverged...)
	}
	return drift, nil
}

func describe(ctx context.Context, admin *kadm.Client, name string) (*kadm.TopicDetail, error) {
	listed, err := admin.ListTopics(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("read the backbone topology: %w", err)
	}
	detail, found := listed[name]
	switch {
	case !found, errors.Is(detail.Err, kerr.UnknownTopicOrPartition):
		return nil, nil
	case detail.Err != nil:
		return nil, fmt.Errorf("read %s: %w", name, detail.Err)
	}
	return &detail, nil
}

func create(ctx context.Context, admin *kadm.Client, topic Topic) (bool, error) {
	declared := make(map[string]*string, 3)
	for _, entry := range topic.settings() {
		declared[entry.key] = kadm.StringPtr(entry.value)
	}

	responses, err := admin.CreateTopics(ctx, topic.Partitions, topic.Replicas, declared, topic.Name)
	if err != nil {
		return false, fmt.Errorf("create %s: %w", topic.Name, err)
	}
	response, err := responses.On(topic.Name, nil)
	if err != nil {
		return false, fmt.Errorf("create %s: %w", topic.Name, err)
	}
	if errors.Is(response.Err, kerr.TopicAlreadyExists) {
		return false, nil
	}
	if response.Err != nil {
		return false, fmt.Errorf("create %s: %w", topic.Name, response.Err)
	}
	return true, nil
}

func shapeAgrees(topic Topic, detail kadm.TopicDetail) error {
	if partitions := int32(len(detail.Partitions)); partitions != topic.Partitions {
		return fmt.Errorf(
			"%s has %d partitions and the topology declares %d: repartitioning ends per-agent ordering and is an explicit operation",
			topic.Name, partitions, topic.Partitions)
	}
	if replicas := int16(detail.Partitions.NumReplicas()); replicas != topic.Replicas {
		return fmt.Errorf(
			"%s keeps %d replicas and the topology declares %d: changing it needs a partition reassignment",
			topic.Name, replicas, topic.Replicas)
	}
	return nil
}

func converge(ctx context.Context, admin *kadm.Client, topic Topic) ([]string, error) {
	diverged, err := diverging(ctx, admin, topic)
	if err != nil || len(diverged) == 0 {
		return nil, err
	}

	alters := make([]kadm.AlterConfig, 0, len(topic.settings()))
	for _, entry := range topic.settings() {
		alters = append(alters, kadm.AlterConfig{Op: kadm.SetConfig, Name: entry.key, Value: kadm.StringPtr(entry.value)})
	}

	responses, err := admin.AlterTopicConfigs(ctx, alters, topic.Name)
	if err != nil {
		return nil, fmt.Errorf("configure %s: %w", topic.Name, err)
	}
	response, err := responses.On(topic.Name, nil)
	if err != nil {
		return nil, fmt.Errorf("configure %s: %w", topic.Name, err)
	}
	if response.Err != nil {
		return nil, fmt.Errorf("configure %s: %w", topic.Name, response.Err)
	}
	return diverged, nil
}

func diverging(ctx context.Context, admin *kadm.Client, topic Topic) ([]string, error) {
	described, err := admin.DescribeTopicConfigs(ctx, topic.Name)
	if err != nil {
		return nil, fmt.Errorf("read the configuration of %s: %w", topic.Name, err)
	}
	resource, err := described.On(topic.Name, nil)
	if err != nil {
		return nil, fmt.Errorf("read the configuration of %s: %w", topic.Name, err)
	}
	if resource.Err != nil {
		return nil, fmt.Errorf("read the configuration of %s: %w", topic.Name, resource.Err)
	}

	current := make(map[string]string, len(resource.Configs))
	for _, entry := range resource.Configs {
		if entry.Value != nil {
			current[entry.Key] = *entry.Value
		}
	}

	var diverged []string
	for _, entry := range topic.settings() {
		if held, known := current[entry.key]; !known || held != entry.value {
			diverged = append(diverged, fmt.Sprintf("%s %s is %q and the topology declares %q",
				topic.Name, entry.key, held, entry.value))
		}
	}
	return diverged, nil
}
