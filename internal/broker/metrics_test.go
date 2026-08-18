package broker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	platformmetrics "github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

func TestLagIncludesFetchedRecordsUntilTheyAreCommitted(t *testing.T) {
	registry := platformmetrics.New("test")
	instruments := NewConsumerMetrics(registry)
	partition := kgo.FetchTopicPartition{
		Topic: "security.events.raw",
		FetchPartition: kgo.FetchPartition{
			Partition:     2,
			HighWatermark: 5000,
			Records: []*kgo.Record{
				{Topic: "security.events.raw", Partition: 2, Offset: 0},
				{Topic: "security.events.raw", Partition: 2, Offset: 4999},
			},
		},
	}

	instruments.observe(partition, -1)

	if got := metricValue(t, registry, `seagull_backbone_consumer_lag_records{partition="2",topic="security.events.raw"}`); got != 5000 {
		t.Fatalf("lag is %.0f, want all 5000 uncommitted records", got)
	}
}

func TestLagKeepsGrowingWithoutAnotherPoll(t *testing.T) {
	registry := platformmetrics.New("test")
	instruments := NewConsumerMetrics(registry)
	partition := fetchedPartition(2, 0, 4999, 5000)
	instruments.observe(partition, -1)

	consumer := Consumer{
		topic:   partition.Topic,
		metrics: instruments,
		endOffsets: staticEndOffsets{offsets: kadm.ListedOffsets{
			partition.Topic: {
				partition.Partition: {
					Topic: partition.Topic, Partition: partition.Partition, Offset: 7500,
				},
			},
		}},
	}
	consumer.refreshLag(context.Background())

	metric := `seagull_backbone_consumer_lag_records{partition="2",topic="security.events.raw"}`
	if got := metricValue(t, registry, metric); got != 7500 {
		t.Fatalf("lag is %.0f, want the uncommitted batch plus newly arrived records", got)
	}

	instruments.committed(fetchesFor(partition))
	if got := metricValue(t, registry, metric); got != 2500 {
		t.Fatalf("lag after commit is %.0f, want only records that arrived later", got)
	}
}

func TestLagRefreshFailureIsObservable(t *testing.T) {
	registry := platformmetrics.New("test")
	instruments := NewConsumerMetrics(registry)
	instruments.observe(fetchedPartition(2, 0, 4999, 5000), -1)
	consumer := Consumer{
		topic:      "security.events.raw",
		metrics:    instruments,
		endOffsets: staticEndOffsets{err: errors.New("broker unavailable")},
	}

	consumer.refreshLag(context.Background())

	metric := `seagull_backbone_consumer_lag_refresh_errors_total{topic="security.events.raw"}`
	if got := metricValue(t, registry, metric); got != 1 {
		t.Fatalf("lag refresh errors are %.0f, want 1", got)
	}
}

type staticEndOffsets struct {
	offsets kadm.ListedOffsets
	err     error
}

func (s staticEndOffsets) ListEndOffsets(context.Context, ...string) (kadm.ListedOffsets, error) {
	return s.offsets, s.err
}

func fetchedPartition(partition int32, first, last, highWatermark int64) kgo.FetchTopicPartition {
	return kgo.FetchTopicPartition{
		Topic: "security.events.raw",
		FetchPartition: kgo.FetchPartition{
			Partition:     partition,
			HighWatermark: highWatermark,
			Records: []*kgo.Record{
				{Topic: "security.events.raw", Partition: partition, Offset: first},
				{Topic: "security.events.raw", Partition: partition, Offset: last},
			},
		},
	}
}

func fetchesFor(partition kgo.FetchTopicPartition) kgo.Fetches {
	return kgo.Fetches{{Topics: []kgo.FetchTopic{{
		Topic:      partition.Topic,
		Partitions: []kgo.FetchPartition{partition.FetchPartition},
	}}}}
}

func metricValue(t *testing.T, registry *platformmetrics.Registry, metric string) float64 {
	t.Helper()

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if !strings.HasPrefix(line, metric+" ") {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimPrefix(line, metric+" "), 64)
		if err != nil {
			t.Fatalf("parse %s: %v", line, err)
		}
		return value
	}
	t.Fatalf("%s was not exposed", metric)
	return 0
}
