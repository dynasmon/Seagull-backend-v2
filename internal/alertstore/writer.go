// Package alertstore is what puts a detection in front of a person: it consumes
// what the analysis engine decided, raises an alert for anything at or above the
// severity a person's time is worth, and keeps it somewhere a lifecycle can act
// on. It evaluates no rule and serves no transport.
package alertstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

const (
	SkipUndecodable = "undecodable"
	SkipBelowFloor  = "below_floor"
	SkipUnraisable  = "unraisable"
)

type Record struct {
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
}

type Deliver func(ctx context.Context, records []Record) error

type Source interface {
	Consume(ctx context.Context, deliver Deliver) error
}

// Raising is idempotent on the alert's name, and answers how many were new: a
// replayed batch finds what it already raised rather than raising it again.
type Sink interface {
	Raise(ctx context.Context, alerts []*alertv1.Alert) (int, error)
}

type WriterOptions struct {
	Source        Source
	Sink          Sink
	Floor         detectionv1.Severity
	Metrics       *Metrics
	Logger        *slog.Logger
	Now           func() time.Time
	WriteTimeout  time.Duration
	RetryDelay    time.Duration
	MaxRetryDelay time.Duration
}

type Writer struct {
	source        Source
	sink          Sink
	floor         detectionv1.Severity
	metrics       *Metrics
	logger        *slog.Logger
	now           func() time.Time
	writeTimeout  time.Duration
	retryDelay    time.Duration
	maxRetryDelay time.Duration
}

func NewWriter(options WriterOptions) (*Writer, error) {
	switch {
	case options.Source == nil:
		return nil, errors.New("the alert writer needs a source")
	case options.Sink == nil:
		return nil, errors.New("the alert writer needs somewhere to raise alerts")
	case options.Floor == detectionv1.Severity_SEVERITY_UNSPECIFIED:
		return nil, errors.New("the alert writer needs a severity floor: raising everything is the same as raising nothing")
	case options.Metrics == nil:
		return nil, errors.New("the alert writer needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the alert writer needs a logger")
	case options.WriteTimeout <= 0:
		return nil, errors.New("the alert writer needs a positive write budget")
	case options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the alert writer needs a retry delay below its ceiling")
	}
	if options.Now == nil {
		options.Now = time.Now
	}

	return &Writer{
		source:        options.Source,
		sink:          options.Sink,
		floor:         options.Floor,
		metrics:       options.Metrics,
		logger:        options.Logger,
		now:           options.Now,
		writeTimeout:  options.WriteTimeout,
		retryDelay:    options.RetryDelay,
		maxRetryDelay: options.MaxRetryDelay,
	}, nil
}

func (w *Writer) Name() string { return "alert-writer" }

func (w *Writer) Run(ctx context.Context) error { return w.source.Consume(ctx, w.handle) }

// A record this cannot use is stepped over and counted rather than quarantined:
// `detection-writer` consumes the same topic and already writes exactly these
// records to its quarantine verbatim, and a second copy from a second consumer
// would double every poison record without saying anything new about it.
func (w *Writer) handle(ctx context.Context, records []Record) error {
	raised := w.raise(records)
	w.metrics.observeBatch(len(records))

	delay := w.retryDelay
	for attempt := 1; ; attempt++ {
		added, err := w.persist(ctx, raised)
		if err == nil {
			w.metrics.batchRaised(len(raised), added)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		w.metrics.batchRetried()
		w.logger.Error("alert_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("alerts", len(raised)),
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

func (w *Writer) raise(records []Record) []*alertv1.Alert {
	at := w.now().UTC()
	raised := make([]*alertv1.Alert, 0, len(records))

	for _, record := range records {
		var decided detectionv1.Detection
		if err := proto.Unmarshal(record.Value, &decided); err != nil {
			w.skip(record, SkipUndecodable, "the record is not a seagull.detection.v1.Detection")
			continue
		}
		if !alert.Raisable(decided.GetSeverity(), w.floor) {
			w.metrics.skipped(SkipBelowFloor)
			continue
		}
		one, err := alert.Raise(&decided, at)
		if err != nil {
			w.skip(record, SkipUnraisable, err.Error())
			continue
		}
		raised = append(raised, one)
	}
	return raised
}

func (w *Writer) persist(ctx context.Context, raised []*alertv1.Alert) (int, error) {
	if len(raised) == 0 {
		return 0, nil
	}

	writeCtx, cancel := context.WithTimeout(ctx, w.writeTimeout)
	defer cancel()

	started := time.Now()
	added, err := w.sink.Raise(writeCtx, raised)
	if err != nil {
		return 0, fmt.Errorf("raise %d alerts: %w", len(raised), err)
	}
	w.metrics.wrote(time.Since(started))
	return added, nil
}

func (w *Writer) skip(record Record, reason, detail string) {
	w.metrics.skipped(reason)
	w.logger.Warn("detection_not_raised",
		slog.String("reason", reason),
		slog.String("detail", detail),
		slog.Int("partition", int(record.Partition)),
		slog.Int64("offset", record.Offset),
	)
}
