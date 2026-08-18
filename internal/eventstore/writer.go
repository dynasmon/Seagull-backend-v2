package eventstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	ReasonUndecodable       = "undecodable"
	ReasonContractViolation = "contract_violation"
	ReasonUnstorable        = "unstorable"
)

type Record struct {
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
}

type Deliver func(ctx context.Context, records []Record) error

// The source advances its position only once a batch has been handled, so a
// crash replays telemetry instead of stepping over it.
type Source interface {
	Consume(ctx context.Context, deliver Deliver) error
}

type Sink interface {
	Store(ctx context.Context, rows []Row) error
}

type Refused struct {
	Key       []byte
	Value     []byte
	Reason    string
	Detail    string
	Partition int32
	Offset    int64
}

type Quarantine interface {
	Publish(ctx context.Context, refused []Refused) error
}

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
		return nil, errors.New("the event writer needs a source")
	case options.Sink == nil:
		return nil, errors.New("the event writer needs a sink")
	case options.Quarantine == nil:
		return nil, errors.New("the event writer needs somewhere to put what it refuses")
	case options.Metrics == nil:
		return nil, errors.New("the event writer needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the event writer needs a logger")
	case options.WriteTimeout <= 0:
		return nil, errors.New("the event writer needs a positive write budget")
	case options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the event writer needs a retry delay below its ceiling")
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

func (w *Writer) Name() string { return "event-writer" }

func (w *Writer) Run(ctx context.Context) error { return w.source.Consume(ctx, w.handle) }

// Retried until durable or stopping; nothing is dropped to make progress. A
// store outage becomes visible consumer lag rather than a gap.
func (w *Writer) handle(ctx context.Context, records []Record) error {
	rows, refused := w.classify(records)
	w.metrics.observeBatch(len(records))

	delay := w.retryDelay
	for attempt := 1; ; attempt++ {
		err := w.persist(ctx, rows, refused)
		if err == nil {
			w.metrics.batchStored()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		w.metrics.batchRetried()
		w.logger.Error("event_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("events", len(rows)),
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

func (w *Writer) classify(records []Record) ([]Row, []Refused) {
	rows := make([]Row, 0, len(records))
	var refused []Refused

	for _, record := range records {
		var decoded eventv1.Event
		if err := proto.Unmarshal(record.Value, &decoded); err != nil {
			refused = append(refused, refuse(record, ReasonUndecodable, "the record is not a seagull.event.v1.Event"))
			continue
		}
		if err := event.ValidateContract(&decoded); err != nil {
			refused = append(refused, refuse(record, ReasonContractViolation, err.Error()))
			continue
		}
		row := Project(&decoded)
		if err := storable(row); err != nil {
			refused = append(refused, refuse(record, ReasonUnstorable, err.Error()))
			continue
		}
		rows = append(rows, row)
	}
	return rows, refused
}

func (w *Writer) persist(ctx context.Context, rows []Row, refused []Refused) error {
	writeCtx, cancel := context.WithTimeout(ctx, w.writeTimeout)
	defer cancel()

	if len(rows) > 0 {
		started := time.Now()
		if err := w.sink.Store(writeCtx, rows); err != nil {
			return fmt.Errorf("store %d events: %w", len(rows), err)
		}
		w.metrics.stored(len(rows), time.Since(started))
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

// The payload is never logged: it can carry attacker input, and the position is
// enough to fetch it from the quarantine topic.
func (w *Writer) report(refused []Refused) {
	for _, entry := range refused {
		w.logger.Warn("event_quarantined",
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
