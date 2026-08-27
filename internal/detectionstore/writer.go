package detectionstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

const (
	ReasonUndecodable = "undecodable"
	ReasonUnstorable  = "unstorable"
)

// The third capability to declare these three, and the reason to keep declaring
// them rather than share one: each says what *this* capability needs of a
// backbone it is not allowed to name, which is what makes the rule that a
// capability may not import another capability mean something. It is nine lines
// and one bridge, held by a test on each side.
type Record struct {
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
}

type Deliver func(ctx context.Context, records []Record) error

// The source advances its position only once a batch has been handled, so a
// crash replays detections instead of stepping over them.
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

// What makes a detection queryable.
//
// It is a consumer of `security.detections` and nothing else: it never reads a
// rule, never evaluates one, and the engine that decides a detection never
// reaches a store. The two meet on the backbone, which is what keeps the shape
// of this table out of the thing that decides what belongs in it.
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
		return nil, errors.New("the detection writer needs a source")
	case options.Sink == nil:
		return nil, errors.New("the detection writer needs a sink")
	case options.Quarantine == nil:
		return nil, errors.New("the detection writer needs somewhere to put what it refuses")
	case options.Metrics == nil:
		return nil, errors.New("the detection writer needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the detection writer needs a logger")
	case options.WriteTimeout <= 0:
		return nil, errors.New("the detection writer needs a positive write budget")
	case options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the detection writer needs a retry delay below its ceiling")
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

func (w *Writer) Name() string { return "detection-writer" }

func (w *Writer) Run(ctx context.Context) error { return w.source.Consume(ctx, w.handle) }

// Retried until durable or stopping; nothing is dropped to make progress. A
// store outage becomes visible consumer lag rather than findings that quietly
// stop being queryable.
//
// A replayed batch writes the rows it already wrote, under the names the engine
// already gave them, so the table replaces rather than accumulates. That is the
// whole reason a detection is named by what decided it.
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
		w.logger.Error("detection_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("detections", len(rows)),
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

// The two ways a record can fail here are separated on purpose, because an
// operator answers them differently: a record that is not a detection is a
// producer to go and find, and a store that will not take one is infrastructure
// to go and fix. Only the first is refused; the second is retried forever.
func (w *Writer) classify(records []Record) ([]Row, []Refused) {
	rows := make([]Row, 0, len(records))
	var refused []Refused

	for _, record := range records {
		var decoded detectionv1.Detection
		if err := proto.Unmarshal(record.Value, &decoded); err != nil {
			refused = append(refused, refuse(record, ReasonUndecodable, "the record is not a seagull.detection.v1.Detection"))
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
			return fmt.Errorf("store %d detections: %w", len(rows), err)
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

// The payload is never logged: a detection carries the evidence, which is a
// value some producer wrote, and the position is enough to fetch it from the
// quarantine topic.
func (w *Writer) report(refused []Refused) {
	for _, entry := range refused {
		w.logger.Warn("detection_quarantined",
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
