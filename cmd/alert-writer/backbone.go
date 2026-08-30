package main

import (
	"context"

	"github.com/dynasmon/Seagull-backend-v2/internal/alertstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
)

// Both packages describe a fetched record and neither imports the other. The
// executable is the only place allowed to know the two line up, which is what
// keeps `internal/alertstore` from learning what a Kafka offset is.

type source struct{ consumer *broker.Consumer }

func (s source) Consume(ctx context.Context, deliver alertstore.Deliver) error {
	return s.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		return deliver(ctx, fetched(records))
	})
}

func fetched(records []broker.Record) []alertstore.Record {
	converted := make([]alertstore.Record, 0, len(records))
	for _, record := range records {
		converted = append(converted, alertstore.Record{
			Partition: record.Partition,
			Offset:    record.Offset,
			Key:       record.Key,
			Value:     record.Value,
		})
	}
	return converted
}
