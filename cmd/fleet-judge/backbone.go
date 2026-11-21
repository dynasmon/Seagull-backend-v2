package main

import (
	"context"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/fleetjudge"
)

// Both packages describe a record read from a log, and neither imports the
// other. The executable is the only place allowed to know the two line up, which
// is what keeps `internal/fleetjudge` from learning what a Kafka offset is.
type whole struct{ reader *broker.StateLog }

func (l whole) Replay(ctx context.Context, deliver fleetjudge.Deliver) error {
	return l.reader.Replay(ctx, bridged(deliver))
}

func (l whole) Follow(ctx context.Context, deliver fleetjudge.Deliver) error {
	return l.reader.Follow(ctx, bridged(deliver))
}

func (l whole) Behind(ctx context.Context) (int64, time.Time, error) { return l.reader.Behind(ctx) }

func bridged(deliver fleetjudge.Deliver) broker.Deliver {
	return func(ctx context.Context, records []broker.Record) error {
		converted := make([]fleetjudge.Record, 0, len(records))
		for _, record := range records {
			converted = append(converted, fleetjudge.Record{
				Partition: record.Partition,
				Offset:    record.Offset,
				Key:       record.Key,
				Value:     record.Value,
				Timestamp: record.Timestamp,
			})
		}
		return deliver(ctx, converted)
	}
}
