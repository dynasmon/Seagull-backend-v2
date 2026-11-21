package agentfindingstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
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
		return nil, errors.New("the agent finding writer needs a source")
	case options.Sink == nil:
		return nil, errors.New("the agent finding writer needs a sink")
	case options.Quarantine == nil:
		return nil, errors.New("the agent finding writer needs somewhere to put what it refuses")
	case options.Metrics == nil:
		return nil, errors.New("the agent finding writer needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the agent finding writer needs a logger")
	case options.WriteTimeout <= 0:
		return nil, errors.New("the agent finding writer needs a positive write budget")
	case options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the agent finding writer needs a retry delay below its ceiling")
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

func (w *Writer) Name() string { return "agent-finding-writer" }

func (w *Writer) Run(ctx context.Context) error { return w.source.Consume(ctx, w.handle) }

// Retried until durable or stopping; nothing is dropped to make progress. A
// store outage costs how current the findings an operator reads are, and never a
// decision the judge made.
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
		w.logger.Error("agent_finding_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("decisions", len(rows)),
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
	var (
		rows    []Row
		refused []Refused
	)
	for _, record := range records {
		var decoded agentv1.Finding
		if err := proto.Unmarshal(record.Value, &decoded); err != nil {
			refused = append(refused, refuse(record, ReasonUndecodable, "the record is not a seagull.agent.v1.Finding"))
			continue
		}
		if err := agentfinding.Validate(&decoded); err != nil {
			refused = append(refused, refuse(record, ReasonContractViolation, err.Error()))
			continue
		}
		rows = append(rows, Project(&decoded, record.Value))
	}
	return rows, refused
}

func (w *Writer) persist(ctx context.Context, rows []Row, refused []Refused) error {
	writeCtx, cancel := context.WithTimeout(ctx, w.writeTimeout)
	defer cancel()

	if len(rows) > 0 {
		started := time.Now()
		if err := w.sink.Store(writeCtx, rows); err != nil {
			return fmt.Errorf("store %d agent finding decisions: %w", len(rows), err)
		}
		w.metrics.stored(rows, time.Since(started))
	}

	if len(refused) > 0 {
		if err := w.quarantine.Publish(writeCtx, refused); err != nil {
			return fmt.Errorf("quarantine %d agent finding records: %w", len(refused), err)
		}
		w.metrics.quarantined(refused)
		for _, entry := range refused {
			w.logger.Warn("agent_finding_quarantined",
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
