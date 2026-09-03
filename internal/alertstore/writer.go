// Package alertstore is what puts a detection in front of a person: it consumes
// what the analysis engine decided and, for anything at or above the severity a
// person's time is worth, opens the work it becomes — an alert for a finding
// about one event, an incident for a story several of them tell together. It
// evaluates no rule and serves no transport.
package alertstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
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

// Where the work goes, in two ports because the two kinds are not the same: an
// alert is raised, folded into one already open, refused for a cooldown or
// recognised as one already recorded, and a story is opened or already open and
// is decided by no tuning. Both are idempotent on the detection that produced
// them, which is what lets a batch be retried whole until the store has all of
// it.
type Sink interface {
	Record(ctx context.Context, candidates []alert.Candidate) ([]alert.Outcome, error)
}

type Stories interface {
	Open(ctx context.Context, stories []*incidentv1.Incident) ([]incident.Outcome, error)
}

type work struct {
	alerts    []alert.Candidate
	incidents []*incidentv1.Incident
}

type WriterOptions struct {
	Source        Source
	Sink          Sink
	Stories       Stories
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
	stories       Stories
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
	case options.Stories == nil:
		return nil, errors.New("the alert writer needs somewhere to open incidents: a story nothing records is a story nobody is told")
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
		stories:       options.Stories,
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
	found := w.consider(records)
	w.metrics.observeBatch(len(records))

	delay := w.retryDelay
	for attempt := 1; ; attempt++ {
		err := w.persist(ctx, found)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		w.metrics.batchRetried()
		w.logger.Error("alert_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("candidates", len(found.alerts)),
			slog.Int("stories", len(found.incidents)),
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
func (w *Writer) consider(records []Record) work {
	at := w.now().UTC()
	found := work{alerts: make([]alert.Candidate, 0, len(records))}

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

		if incident.Correlates(&decided) {
			story, err := incident.Raise(&decided, at)
			if err != nil {
				w.skip(record, SkipUnraisable, err.Error())
				continue
			}
			found.incidents = append(found.incidents, story)
			continue
		}

		candidate, err := alert.Consider(&decided, w.tuning, at)
		if err != nil {
			w.skip(record, SkipUnraisable, err.Error())
			continue
		}
		found.alerts = append(found.alerts, candidate)
	}
	return found
}

func (w *Writer) persist(ctx context.Context, found work) error {
	if len(found.alerts) == 0 && len(found.incidents) == 0 {
		return nil
	}

	writeCtx, cancel := context.WithTimeout(ctx, w.writeTimeout)
	defer cancel()
	started := time.Now()

	if len(found.alerts) > 0 {
		outcomes, err := w.sink.Record(writeCtx, found.alerts)
		if err != nil {
			return fmt.Errorf("record %d detections: %w", len(found.alerts), err)
		}
		w.metrics.alertsRecorded(outcomes)
	}
	if len(found.incidents) > 0 {
		opened, err := w.stories.Open(writeCtx, found.incidents)
		if err != nil {
			return fmt.Errorf("open %d incidents: %w", len(found.incidents), err)
		}
		w.metrics.storiesOpened(opened)
	}

	w.metrics.batchStored()
	w.metrics.wrote(time.Since(started))
	return nil
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
