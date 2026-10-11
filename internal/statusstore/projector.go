package statusstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

type ProjectorOptions struct {
	Source        Source
	Sink          Sink
	Quarantine    Quarantine
	Metrics       *Metrics
	Logger        *slog.Logger
	WriteTimeout  time.Duration
	RetryDelay    time.Duration
	MaxRetryDelay time.Duration
}

type Projector struct {
	source        Source
	sink          Sink
	quarantine    Quarantine
	metrics       *Metrics
	logger        *slog.Logger
	writeTimeout  time.Duration
	retryDelay    time.Duration
	maxRetryDelay time.Duration
}

func NewProjector(options ProjectorOptions) (*Projector, error) {
	switch {
	case options.Source == nil:
		return nil, errors.New("the status projector needs a source")
	case options.Sink == nil:
		return nil, errors.New("the status projector needs a sink")
	case options.Quarantine == nil:
		return nil, errors.New("the status projector needs somewhere to put what it refuses")
	case options.Metrics == nil:
		return nil, errors.New("the status projector needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the status projector needs a logger")
	case options.WriteTimeout <= 0:
		return nil, errors.New("the status projector needs a positive write budget")
	case options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the status projector needs a retry delay below its ceiling")
	}

	return &Projector{
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

func (p *Projector) Name() string { return "status-projector" }

func (p *Projector) Run(ctx context.Context) error { return p.source.Consume(ctx, p.handle) }

// Retried until durable or stopping; nothing is dropped to make progress. A
// store outage costs freshness and shows as consumer lag, and never an agent
// that looks silent because its reports were skipped.
func (p *Projector) handle(ctx context.Context, records []Record) error {
	rows, refused := p.classify(records)
	p.metrics.observeBatch(len(records))

	delay := p.retryDelay
	for attempt := 1; ; attempt++ {
		err := p.persist(ctx, rows, refused)
		if err == nil {
			p.metrics.batchStored()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		p.metrics.batchRetried()
		p.logger.Error("status_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("reports", len(rows)),
			slog.Int("refused", len(refused)),
			slog.Duration("retry_in", delay),
			slog.String("error", err.Error()),
		)

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
		delay = min(delay*2, p.maxRetryDelay)
	}
}

func (p *Projector) classify(records []Record) ([]Row, []Refused) {
	var (
		rows    []Row
		refused []Refused
	)
	for _, record := range records {
		var decoded agentv1.Status
		if err := proto.Unmarshal(record.Value, &decoded); err != nil {
			refused = append(refused, refuse(record, ReasonUndecodable, "the record is not a seagull.agent.v1.Status"))
			continue
		}
		if err := agentstatus.ValidateContract(&decoded); err != nil {
			refused = append(refused, refuse(record, ReasonContractViolation, err.Error()))
			continue
		}
		row := Project(&decoded, record.Value)
		if err := storable(row); err != nil {
			refused = append(refused, refuse(record, ReasonUnstorable, err.Error()))
			continue
		}
		rows = append(rows, row)
	}
	return rows, refused
}

func (p *Projector) persist(ctx context.Context, rows []Row, refused []Refused) error {
	writeCtx, cancel := context.WithTimeout(ctx, p.writeTimeout)
	defer cancel()

	if len(rows) > 0 {
		started := time.Now()
		if err := p.sink.Store(writeCtx, rows); err != nil {
			return fmt.Errorf("store %d reports: %w", len(rows), err)
		}
		p.metrics.stored(rows, time.Since(started))
	}

	if len(refused) > 0 {
		if err := p.quarantine.Publish(writeCtx, refused); err != nil {
			return fmt.Errorf("quarantine %d reports: %w", len(refused), err)
		}
		p.metrics.quarantined(refused)
		for _, entry := range refused {
			p.logger.Warn("status_quarantined",
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
