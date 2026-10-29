package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

// What an acknowledgement from the backbone is worth. A production backbone
// keeps every record on three replicas and acknowledges one only once two hold
// it, so losing a broker loses nothing it acknowledged; anything less is a
// development backbone, and a deployment says so rather than inheriting it.
type Durability int

const (
	Production Durability = iota
	Development
)

const (
	productionReplicas = 3
	productionInSync   = 2

	durabilityKey = "SEAGULL_BACKBONE_DURABILITY"
)

func (d Durability) String() string {
	switch d {
	case Production:
		return "production"
	case Development:
		return "development"
	default:
		return fmt.Sprintf("durability(%d)", int(d))
	}
}

var ErrBelowProductionDurability = errors.New("below the durability a production backbone keeps")

// Kafka acknowledges a write once every in-sync replica holds it and refuses
// one below min.insync.replicas; Redpanda acknowledges once a Raft majority
// holds it and does not answer for the setting. The fewer of the two is what
// either broker guarantees.
func (t Topic) acknowledgedBy() int16 { return min(t.MinInSync, t.Replicas/2+1) }

func weakest(topics []Topic) (Topic, bool) {
	if len(topics) == 0 {
		return Topic{}, false
	}
	held := topics[0]
	for _, topic := range topics[1:] {
		if topic.acknowledgedBy() < held.acknowledgedBy() {
			held = topic
		}
	}
	return held, true
}

func LogDurability(ctx context.Context, logger *slog.Logger, topics ...Topic) {
	held, found := weakest(topics)
	if !found {
		return
	}
	level := slog.LevelInfo
	if held.Durability == Development || held.acknowledgedBy() < productionInSync {
		level = slog.LevelWarn
	}
	logger.Log(ctx, level, "backbone_durability",
		slog.String("durability", held.Durability.String()),
		slog.Int("replicas", int(held.Replicas)),
		slog.Int("min_in_sync_replicas", int(held.MinInSync)),
		slog.Int("acknowledged_by", int(held.acknowledgedBy())),
	)
}

func ObserveDurability(registry *metrics.Registry, topics ...Topic) {
	held, found := weakest(topics)
	if !found {
		return
	}
	acknowledging := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metrics.Namespace,
		Subsystem: "backbone",
		Name:      "acknowledging_replicas",
		Help:      "Fewest replicas that hold a record once the backbone acknowledges it, as declared and verified at startup.",
	})
	acknowledging.Set(float64(held.acknowledgedBy()))
	registry.MustRegister(acknowledging)
}
