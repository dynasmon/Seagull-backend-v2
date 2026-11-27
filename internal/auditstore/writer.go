package auditstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/audit"
	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
)

type WriterOptions struct {
	Source        Source
	Store         Store
	Quarantine    Quarantine
	Metrics       *Metrics
	Logger        *slog.Logger
	WriteTimeout  time.Duration
	RetryDelay    time.Duration
	MaxRetryDelay time.Duration
}

type Writer struct {
	source        Source
	store         Store
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
		return nil, errors.New("the audit writer needs a source")
	case options.Store == nil:
		return nil, errors.New("the audit writer needs a store")
	case options.Quarantine == nil:
		return nil, errors.New("the audit writer needs somewhere to put what it refuses")
	case options.Metrics == nil:
		return nil, errors.New("the audit writer needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the audit writer needs a logger")
	case options.WriteTimeout <= 0:
		return nil, errors.New("the audit writer needs a positive write budget")
	case options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the audit writer needs a retry delay below its ceiling")
	}

	return &Writer{
		source:        options.Source,
		store:         options.Store,
		quarantine:    options.Quarantine,
		metrics:       options.Metrics,
		logger:        options.Logger,
		writeTimeout:  options.WriteTimeout,
		retryDelay:    options.RetryDelay,
		maxRetryDelay: options.MaxRetryDelay,
	}, nil
}

func (w *Writer) Name() string { return "audit-writer" }

func (w *Writer) Run(ctx context.Context) error { return w.source.Consume(ctx, w.handle) }

// Retried until durable or stopping, and every attempt decides the batch again
// from what the store holds then: an entry an attempt wrote before it failed is
// found chained by the next one, never chained twice. Nothing is skipped to make
// progress, so a store outage costs how current the trail is and never an event.
func (w *Writer) handle(ctx context.Context, records []Record) error {
	batch, refused := classify(records)
	w.metrics.observeBatch(len(records))

	delay := w.retryDelay
	for attempt := 1; ; attempt++ {
		result, err := w.persist(ctx, batch, refused)
		if err == nil {
			w.metrics.stored(result, refused)
			w.report(slices.Concat(refused, result.misplaced))
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		w.metrics.retried(errors.Is(err, errUnordered))
		w.logger.Error("audit_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("events", len(batch)),
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

func (w *Writer) persist(ctx context.Context, batch []admitted, refused []Refused) (linked, error) {
	writeCtx, cancel := context.WithTimeout(ctx, w.writeTimeout)
	defer cancel()

	var result linked
	if len(batch) > 0 {
		chained, err := w.store.Chained(writeCtx, asked(batch))
		if err != nil {
			return linked{}, fmt.Errorf("decide %d audit events: %w", len(batch), err)
		}
		heads, err := w.store.Heads(writeCtx, chainsOf(batch))
		if err != nil {
			return linked{}, fmt.Errorf("decide %d audit events: %w", len(batch), err)
		}
		if result, err = link(batch, heads, chained); err != nil {
			return linked{}, err
		}
		if len(result.rows) > 0 {
			started := time.Now()
			if err := w.store.Append(writeCtx, result.rows); err != nil {
				return linked{}, fmt.Errorf("append %d audit entries: %w", len(result.rows), err)
			}
			w.metrics.wrote(time.Since(started))
		}
	}

	quarantined := slices.Concat(refused, result.misplaced)
	if len(quarantined) > 0 {
		if err := w.quarantine.Publish(writeCtx, quarantined); err != nil {
			return linked{}, fmt.Errorf("quarantine %d audit records: %w", len(quarantined), err)
		}
	}
	return result, nil
}

func (w *Writer) report(quarantined []Refused) {
	for _, entry := range quarantined {
		w.logger.Warn("audit_record_quarantined",
			slog.String("reason", entry.Reason),
			slog.String("detail", entry.Detail),
			slog.Int("partition", int(entry.Partition)),
			slog.Int64("offset", entry.Offset),
		)
	}
}

// A record is keyed by the chain its event belongs to, because the key is what
// keeps a chain on one partition: one keyed otherwise could start or extend a
// chain on a partition another writer reads.
func classify(records []Record) ([]admitted, []Refused) {
	var (
		batch   []admitted
		refused []Refused
	)
	for _, record := range records {
		var recorded auditv1.Event
		if err := proto.Unmarshal(record.Value, &recorded); err != nil {
			refused = append(refused, refuse(record, ReasonUndecodable, "the record is not a seagull.audit.v1.Event"))
			continue
		}
		if err := audit.Validate(&recorded); err != nil {
			refused = append(refused, refuse(record, ReasonContractViolation, err.Error()))
			continue
		}
		if !bytes.Equal(record.Key, []byte(recorded.GetTenantId())) {
			refused = append(refused, refuse(record, ReasonMisplaced, "the record is keyed for another chain"))
			continue
		}
		batch = append(batch, admitted{record: record, recorded: &recorded})
	}
	return batch, refused
}
