package inventorystore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
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
		return nil, errors.New("the inventory projector needs a source")
	case options.Sink == nil:
		return nil, errors.New("the inventory projector needs a sink")
	case options.Quarantine == nil:
		return nil, errors.New("the inventory projector needs somewhere to put what it refuses")
	case options.Metrics == nil:
		return nil, errors.New("the inventory projector needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the inventory projector needs a logger")
	case options.WriteTimeout <= 0:
		return nil, errors.New("the inventory projector needs a positive write budget")
	case options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the inventory projector needs a retry delay below its ceiling")
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

func (p *Projector) Name() string { return "inventory-projector" }

func (p *Projector) Run(ctx context.Context) error { return p.source.Consume(ctx, p.handle) }

// Retried until durable or stopping; nothing is dropped to make progress. A
// store outage becomes visible consumer lag rather than an asset whose inventory
// quietly stopped moving.
func (p *Projector) handle(ctx context.Context, records []Record) error {
	rows, scans, refused := p.classify(records)
	p.metrics.observeBatch(len(records))

	delay := p.retryDelay
	for attempt := 1; ; attempt++ {
		err := p.persist(ctx, len(records)-len(refused), rows, scans, refused)
		if err == nil {
			p.metrics.batchStored()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		p.metrics.batchRetried()
		p.logger.Error("inventory_batch_not_durable",
			slog.Int("attempt", attempt),
			slog.Int("items", len(rows)),
			slog.Int("scans", len(scans)),
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

// A record is folded whole or refused whole. One item this build cannot store
// takes its scan with it, because a scan whose items never landed would retire
// everything the record was going to confirm.
func (p *Projector) classify(records []Record) ([]Row, []Scan, []Refused) {
	var (
		rows    []Row
		scans   []Scan
		refused []Refused
	)

	for _, record := range records {
		var decoded inventoryv1.Record
		if err := proto.Unmarshal(record.Value, &decoded); err != nil {
			refused = append(refused, refuse(record, ReasonUndecodable, "the record is not a seagull.inventory.v1.Record"))
			continue
		}
		if err := inventory.ValidateContract(&decoded); err != nil {
			refused = append(refused, refuse(record, ReasonContractViolation, err.Error()))
			continue
		}

		projected := Project(&decoded)
		unstorable := ""
		for _, row := range projected {
			if err := storable(row); err != nil {
				unstorable = err.Error()
				break
			}
		}
		if unstorable != "" {
			refused = append(refused, refuse(record, ReasonUnstorable, unstorable))
			continue
		}

		rows = append(rows, projected...)
		if enumerated, full := Scanned(&decoded); full {
			scans = append(scans, enumerated)
		}
	}
	return rows, scans, refused
}

func (p *Projector) persist(ctx context.Context, folded int, rows []Row, scans []Scan, refused []Refused) error {
	writeCtx, cancel := context.WithTimeout(ctx, p.writeTimeout)
	defer cancel()

	if len(rows) > 0 || len(scans) > 0 {
		started := time.Now()
		if err := p.sink.Store(writeCtx, rows, scans); err != nil {
			return fmt.Errorf("store %d items and %d scans: %w", len(rows), len(scans), err)
		}
		p.metrics.stored(folded, rows, scans, time.Since(started))
	}

	if len(refused) > 0 {
		if err := p.quarantine.Publish(writeCtx, refused); err != nil {
			return fmt.Errorf("quarantine %d records: %w", len(refused), err)
		}
		p.metrics.quarantined(refused)
		p.report(refused)
	}
	return nil
}

// The payload is never logged: it can carry attacker input, and the position is
// enough to fetch it from the quarantine topic.
func (p *Projector) report(refused []Refused) {
	for _, entry := range refused {
		p.logger.Warn("inventory_quarantined",
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
