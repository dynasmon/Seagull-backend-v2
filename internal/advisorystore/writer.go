package advisorystore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

type WriterOptions struct {
	Source        Source
	Sink          Sink
	Quarantine    Quarantine
	Metrics       *Metrics
	Logger        *slog.Logger
	WriteTimeout  time.Duration
	RetryDelay    time.Duration
	MaxRetryDelay time.Duration
}

type Writer struct {
	source        Source
	sink          Sink
	quarantine    Quarantine
	metrics       *Metrics
	logger        *slog.Logger
	writeTimeout  time.Duration
	retryDelay    time.Duration
	maxRetryDelay time.Duration
}

func NewWriter(options WriterOptions) (*Writer, error) {
	switch {
	case options.Source == nil:
		return nil, errors.New("the advisory writer needs a source")
	case options.Sink == nil:
		return nil, errors.New("the advisory writer needs a sink")
	case options.Quarantine == nil:
		return nil, errors.New("the advisory writer needs somewhere to put what it refuses")
	case options.Metrics == nil:
		return nil, errors.New("the advisory writer needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the advisory writer needs a logger")
	case options.WriteTimeout <= 0:
		return nil, errors.New("the advisory writer needs a positive write budget")
	case options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the advisory writer needs a retry delay below its ceiling")
	}

	return &Writer{
		source:        options.Source,
		sink:          options.Sink,
		quarantine:    options.Quarantine,
		metrics:       options.Metrics,
		logger:        options.Logger,
		writeTimeout:  options.WriteTimeout,
		retryDelay:    options.RetryDelay,
		maxRetryDelay: options.MaxRetryDelay,
	}, nil
}

func (w *Writer) Name() string { return "advisory-writer" }

func (w *Writer) Run(ctx context.Context) error { return w.source.Consume(ctx, w.handle) }

// Retried until durable or stopping; nothing is dropped to make progress. A
// store outage becomes visible consumer lag rather than intelligence that
// quietly stopped arriving.
func (w *Writer) handle(ctx context.Context, records []Record) error {
	projected, refused := w.classify(records)
	w.metrics.observeBatch(len(records))

	delay := w.retryDelay
	for attempt := 1; ; attempt++ {
		err := w.persist(ctx, len(records)-len(refused), projected, refused)
		if err == nil {
			w.metrics.batchStored()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		w.metrics.batchRetried()
		w.logger.Error("advisory_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("advisories", len(projected.Advisories)),
			slog.Int("affected", len(projected.Affected)),
			slog.Int("syncs", len(projected.Syncs)),
			slog.Int("refused", len(refused)),
			slog.Duration("retry_in", delay),
			slog.String("error", err.Error()),
		)

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
		delay = min(delay*2, w.maxRetryDelay)
	}
}

// An advisory is stored whole or refused whole: a version whose packages never
// landed would read as affecting nothing, which is the one wrong answer a
// matcher cannot tell from a right one.
func (w *Writer) classify(records []Record) (Projection, []Refused) {
	var (
		projected Projection
		refused   []Refused
	)
	for _, record := range records {
		var decoded vulnerabilityv1.Record
		if err := proto.Unmarshal(record.Value, &decoded); err != nil {
			refused = append(refused, refuse(record, ReasonUndecodable, "the record is not a seagull.vulnerability.v1.Record"))
			continue
		}
		if err := vulnerability.ValidateRecord(&decoded); err != nil {
			refused = append(refused, refuse(record, ReasonContractViolation, err.Error()))
			continue
		}
		projected.add(Project(&decoded))
	}
	return projected, refused
}

func (w *Writer) persist(ctx context.Context, written int, projected Projection, refused []Refused) error {
	writeCtx, cancel := context.WithTimeout(ctx, w.writeTimeout)
	defer cancel()

	if !projected.empty() {
		started := time.Now()
		if err := w.sink.Store(writeCtx, projected); err != nil {
			return fmt.Errorf("store %d advisories, %d affected packages and %d syncs: %w",
				len(projected.Advisories), len(projected.Affected), len(projected.Syncs), err)
		}
		w.metrics.stored(written, projected, time.Since(started))
	}

	if len(refused) > 0 {
		if err := w.quarantine.Publish(writeCtx, refused); err != nil {
			return fmt.Errorf("quarantine %d records: %w", len(refused), err)
		}
		w.metrics.quarantined(refused)
		w.report(refused)
	}
	return nil
}

// The payload is never logged: it is what a feed on the internet wrote, and
// the position is enough to fetch it from the quarantine topic.
func (w *Writer) report(refused []Refused) {
	for _, entry := range refused {
		w.logger.Warn("advisory_quarantined",
			slog.String("reason", entry.Reason),
			slog.String("detail", entry.Detail),
			slog.Int("partition", int(entry.Partition)),
			slog.Int64("offset", entry.Offset),
		)
	}
}

func refuse(record Record, reason, detail string) Refused {
	return Refused{
		Key:       record.Key,
		Value:     record.Value,
		Reason:    reason,
		Detail:    detail,
		Partition: record.Partition,
		Offset:    record.Offset,
	}
}
