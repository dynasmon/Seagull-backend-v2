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

// Every candidate is decided the same way and answered for one by one: raised,
// folded into one already open, refused for a cooldown, or recognised as one
// already recorded. Idempotent on the detection id, which is what lets a batch
// be retried until the store takes it.
type Sink interface {
	Record(ctx context.Context, candidates []alert.Candidate) ([]alert.Outcome, error)
}

type WriterOptions struct {
	Source        Source
	Sink          Sink
	Tuning        *alert.Tuning
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
	tuning        *alert.Tuning
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
	case options.Tuning == nil:
		return nil, errors.New("the alert writer needs a tuning: how alerts fold is declared, never assumed")
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
		tuning:        options.Tuning,
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
	candidates := w.consider(records)
	w.metrics.observeBatch(len(records))

	delay := w.retryDelay
	for attempt := 1; ; attempt++ {
		outcomes, err := w.persist(ctx, candidates)
		if err == nil {
			w.metrics.batchRecorded(outcomes)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		w.metrics.batchRetried()
		w.logger.Error("alert_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("candidates", len(candidates)),
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

// Suppression is decided here and never in the store: a detection the estate
// said it does not want is counted by rule and reason and never written, and it
// stays in the detection store either way, so what was hidden is the work and
// never the activity.
func (w *Writer) consider(records []Record) []alert.Candidate {
	at := w.now().UTC()
	candidates := make([]alert.Candidate, 0, len(records))

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
		if hidden, suppressed := w.tuning.Suppressed(&decided, alert.Happened(&decided, at)); suppressed {
			w.metrics.suppressed(decided.GetRule().GetId(), hidden.Reason)
			continue
		}
		candidate, err := alert.Consider(&decided, w.tuning, at)
		if err != nil {
			w.skip(record, SkipUnraisable, err.Error())
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func (w *Writer) persist(ctx context.Context, candidates []alert.Candidate) ([]alert.Outcome, error) {
	if len(candidates) == 0 {
		return nil, nil
	}

	writeCtx, cancel := context.WithTimeout(ctx, w.writeTimeout)
	defer cancel()

	started := time.Now()
	outcomes, err := w.sink.Record(writeCtx, candidates)
	if err != nil {
		return nil, fmt.Errorf("record %d detections: %w", len(candidates), err)
	}
	w.metrics.wrote(time.Since(started))
	return outcomes, nil
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
