package findingstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/finding"
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
		return nil, errors.New("the finding writer needs a source")
	case options.Sink == nil:
		return nil, errors.New("the finding writer needs a sink")
	case options.Quarantine == nil:
		return nil, errors.New("the finding writer needs somewhere to put what it refuses")
	case options.Metrics == nil:
		return nil, errors.New("the finding writer needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the finding writer needs a logger")
	case options.WriteTimeout <= 0:
		return nil, errors.New("the finding writer needs a positive write budget")
	case options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the finding writer needs a retry delay below its ceiling")
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

func (w *Writer) Name() string { return "finding-writer" }

func (w *Writer) Run(ctx context.Context) error { return w.source.Consume(ctx, w.handle) }

// Retried until durable or stopping; nothing is dropped to make progress. The
// matcher reads what this wrote to label what it decides next, so a store
// outage is lag it waits on, and never a decision it labels without its past.
func (w *Writer) handle(ctx context.Context, records []Record) error {
	findings, assessments, refused := w.classify(records)
	w.metrics.observeBatch(len(records))

	delay := w.retryDelay
	for attempt := 1; ; attempt++ {
		err := w.persist(ctx, findings, assessments, refused)
		if err == nil {
			w.metrics.batchStored()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		w.metrics.batchRetried()
		w.logger.Error("finding_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("findings", len(findings)),
			slog.Int("assessments", len(assessments)),
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

func (w *Writer) classify(records []Record) ([]FindingRow, []AssessmentRow, []Refused) {
	var (
		findings    []FindingRow
		assessments []AssessmentRow
		refused     []Refused
	)
	for _, record := range records {
		var decoded vulnerabilityv1.FindingRecord
		if err := proto.Unmarshal(record.Value, &decoded); err != nil {
			refused = append(refused, refuse(record, ReasonUndecodable, "the record is not a seagull.vulnerability.v1.FindingRecord"))
			continue
		}
		if err := finding.ValidateRecord(&decoded); err != nil {
			refused = append(refused, refuse(record, ReasonContractViolation, err.Error()))
			continue
		}
		switch body := decoded.GetRecord().(type) {
		case *vulnerabilityv1.FindingRecord_Finding:
			findings = append(findings, ProjectFinding(body.Finding, record.Value))
		case *vulnerabilityv1.FindingRecord_Assessment:
			assessments = append(assessments, ProjectAssessment(body.Assessment, record.Value))
		}
	}
	return findings, assessments, refused
}

func (w *Writer) persist(ctx context.Context, findings []FindingRow, assessments []AssessmentRow, refused []Refused) error {
	writeCtx, cancel := context.WithTimeout(ctx, w.writeTimeout)
	defer cancel()

	if len(findings) > 0 || len(assessments) > 0 {
		started := time.Now()
		if err := w.sink.Store(writeCtx, findings, assessments); err != nil {
			return fmt.Errorf("store %d findings and %d assessments: %w", len(findings), len(assessments), err)
		}
		w.metrics.stored(findings, assessments, time.Since(started))
	}

	if len(refused) > 0 {
		if err := w.quarantine.Publish(writeCtx, refused); err != nil {
			return fmt.Errorf("quarantine %d finding records: %w", len(refused), err)
		}
		w.metrics.quarantined(refused)
		for _, entry := range refused {
			w.logger.Warn("finding_quarantined",
				slog.String("reason", entry.Reason),
				slog.String("detail", entry.Detail),
				slog.Int("partition", int(entry.Partition)),
				slog.Int64("offset", entry.Offset),
			)
		}
	}
	return nil
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
