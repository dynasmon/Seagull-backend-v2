package main

import (
	"context"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
)

// The same bridge the writer needs, for the same reason: both packages describe
// a fetched record and neither imports the other, so the executable is the only
// place allowed to know the two line up.

type source struct{ consumer *broker.Consumer }

func (s source) Consume(ctx context.Context, deliver analysis.Deliver) error {
	return s.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		return deliver(ctx, fetched(records))
	})
}

func fetched(records []broker.Record) []analysis.Record {
	converted := make([]analysis.Record, 0, len(records))
	for _, record := range records {
		converted = append(converted, analysis.Record{
			Partition: record.Partition,
			Offset:    record.Offset,
			Key:       record.Key,
			Value:     record.Value,
		})
	}
	return converted
}
