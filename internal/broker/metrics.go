package broker

import (
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

func label(partition int32) string { return strconv.FormatInt(int64(partition), 10) }

type ConsumerMetrics struct {
	records      *prometheus.CounterVec
	fetches      *prometheus.CounterVec
	commits      prometheus.Counter
	lagRefreshes *prometheus.CounterVec
	lag          *prometheus.GaugeVec
	mu           sync.Mutex
	positions    map[lagPartition]lagPosition
}

type lagPartition struct {
	topic     string
	partition int32
}

type lagPosition struct {
	next int64
	end  int64
}

// Keep labels bounded to topic and partition.
func NewConsumerMetrics(registry *metrics.Registry) *ConsumerMetrics {
	instruments := &ConsumerMetrics{
		records: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "backbone",
			Name:      "records_fetched_total",
			Help:      "Records fetched from the backbone.",
		}, []string{"topic"}),
		fetches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "backbone",
			Name:      "fetch_errors_total",
			Help:      "Failed fetches, by topic and partition.",
		}, []string{"topic", "partition"}),
		commits: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "backbone",
			Name:      "commit_errors_total",
			Help:      "Refused attempts to advance the group position.",
		}),
		lagRefreshes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "backbone",
			Name:      "consumer_lag_refresh_errors_total",
			Help:      "Failed attempts to refresh partition end offsets.",
		}, []string{"topic"}),
		lag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "backbone",
			Name:      "consumer_lag_records",
			Help:      "Records between the committed processing position and the end of the partition.",
		}, []string{"topic", "partition"}),
		positions: make(map[lagPartition]lagPosition),
	}
	registry.MustRegister(
		instruments.records,
		instruments.fetches,
		instruments.commits,
		instruments.lagRefreshes,
		instruments.lag,
	)
	return instruments
}

func (m *ConsumerMetrics) observe(partition kgo.FetchTopicPartition, committed int64) {
	count := len(partition.Records)
	if count > 0 {
		m.records.WithLabelValues(partition.Topic).Add(float64(count))
	}

	next := committed
	if next < 0 {
		next = partition.HighWatermark
		if count > 0 {
			next = partition.Records[0].Offset
		}
	}
	m.track(partition.Topic, partition.Partition, next, partition.HighWatermark)
}

func (m *ConsumerMetrics) committed(fetches kgo.Fetches) {
	fetches.EachPartition(func(partition kgo.FetchTopicPartition) {
		count := len(partition.Records)
		if count > 0 {
			m.advance(partition.Topic, partition.Partition, partition.Records[count-1].Offset+1)
		}
	})
}

func (m *ConsumerMetrics) track(topic string, partition int32, next, end int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := lagPartition{topic: topic, partition: partition}
	position, exists := m.positions[key]
	if !exists {
		position.next = next
	}
	position.end = end
	m.positions[key] = position
	m.publishLocked(key, position)
}

func (m *ConsumerMetrics) advance(topic string, partition int32, next int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := lagPartition{topic: topic, partition: partition}
	position, exists := m.positions[key]
	if !exists {
		position = lagPosition{next: next, end: next}
	} else if next > position.next {
		position.next = next
	}
	m.positions[key] = position
	m.publishLocked(key, position)
}

func (m *ConsumerMetrics) refresh(topic string, partition int32, end int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := lagPartition{topic: topic, partition: partition}
	position, exists := m.positions[key]
	if !exists {
		return
	}
	position.end = end
	m.positions[key] = position
	m.publishLocked(key, position)
}

func (m *ConsumerMetrics) tracks(topic string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.positions {
		if key.topic == topic {
			return true
		}
	}
	return false
}

func (m *ConsumerMetrics) publishLocked(key lagPartition, position lagPosition) {
	lag := max(position.end-position.next, 0)
	m.lag.WithLabelValues(key.topic, label(key.partition)).Set(float64(lag))
}

func (m *ConsumerMetrics) fetchFailed(topic string, partition int32) {
	m.fetches.WithLabelValues(topic, label(partition)).Inc()
}

func (m *ConsumerMetrics) commitFailed() { m.commits.Inc() }

func (m *ConsumerMetrics) lagRefreshFailed(topic string) {
	m.lagRefreshes.WithLabelValues(topic).Inc()
}

// Remove revoked partitions rather than exposing stale ownership.
func (m *ConsumerMetrics) forget(revoked map[string][]int32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for topic, partitions := range revoked {
		for _, partition := range partitions {
			delete(m.positions, lagPartition{topic: topic, partition: partition})
			m.lag.DeleteLabelValues(topic, label(partition))
		}
	}
}
