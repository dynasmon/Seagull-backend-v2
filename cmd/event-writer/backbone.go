package main

import (
	"context"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
)

// Both packages describe a fetched and a refused record, and neither imports the
// other. The executable is the only place allowed to know the two line up, which
// is what keeps `internal/eventstore` from learning what a Kafka offset is.

type source struct{ consumer *broker.Consumer }

func (s source) Consume(ctx context.Context, deliver eventstore.Deliver) error {
	return s.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		return deliver(ctx, fetched(records))
	})
}

func fetched(records []broker.Record) []eventstore.Record {
	converted := make([]eventstore.Record, 0, len(records))
	for _, record := range records {
		converted = append(converted, eventstore.Record{
			Partition: record.Partition,
			Offset:    record.Offset,
			Key:       record.Key,
			Value:     record.Value,
		})
	}
	return converted
}

type quarantine struct{ topic *broker.Quarantine }

func (q quarantine) Publish(ctx context.Context, refused []eventstore.Refused) error {
	return q.topic.Publish(ctx, rejected(refused))
}

func rejected(refused []eventstore.Refused) []broker.Refused {
	converted := make([]broker.Refused, 0, len(refused))
	for _, entry := range refused {
		converted = append(converted, broker.Refused{
			Key:       entry.Key,
			Value:     entry.Value,
			Reason:    entry.Reason,
			Detail:    entry.Detail,
			Partition: entry.Partition,
			Offset:    entry.Offset,
		})
	}
	return converted
}
