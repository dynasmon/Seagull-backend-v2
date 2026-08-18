package broker

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

func label(partition int32) string { return strconv.FormatInt(int64(partition), 10) }

type ConsumerMetrics struct {
	records *prometheus.CounterVec
	fetches *prometheus.CounterVec
	commits prometheus.Counter
	lag     *prometheus.GaugeVec
}

// Labels stop at topic and partition: v1 lost a metrics backend to per-path and
// per-identifier labels.
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
		lag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "backbone",
			Name:      "consumer_lag_records",
			Help:      "Records between the last one handed to the consumer and the end of the partition.",
		}, []string{"topic", "partition"}),
	}
	registry.MustRegister(
		instruments.records,
		instruments.fetches,
		instruments.commits,
		instruments.lag,
	)
	return instruments
}

func (m *ConsumerMetrics) observe(partition kgo.FetchTopicPartition) {
	count := len(partition.Records)
	if count == 0 {
		return
	}
	m.records.WithLabelValues(partition.Topic).Add(float64(count))

	last := partition.Records[count-1].Offset
	lag := partition.HighWatermark - last - 1
	if lag < 0 {
		lag = 0
	}
	m.lag.WithLabelValues(partition.Topic, label(partition.Partition)).Set(float64(lag))
}

func (m *ConsumerMetrics) fetchFailed(topic string, partition int32) {
	m.fetches.WithLabelValues(topic, label(partition)).Inc()
}

func (m *ConsumerMetrics) commitFailed() { m.commits.Inc() }

// A revoked partition has no lag to report, and a stale value would describe a
// backlog nobody owns.
func (m *ConsumerMetrics) forget(revoked map[string][]int32) {
	for topic, partitions := range revoked {
		for _, partition := range partitions {
			m.lag.DeleteLabelValues(topic, label(partition))
		}
	}
}
