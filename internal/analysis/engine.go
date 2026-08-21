package analysis

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	ReasonUndecodable       = "undecodable"
	ReasonContractViolation = "contract_violation"
)

type Record struct {
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
}

type Deliver func(ctx context.Context, records []Record) error

// The source advances its position only once a batch has been analysed, so a
// crash replays telemetry instead of stepping over it.
type Source interface {
	Consume(ctx context.Context, deliver Deliver) error
}

type EngineOptions struct {
	Source  Source
	Metrics *Metrics
	Logger  *slog.Logger
}

// The second consumer of the raw telemetry the gateway admitted, and the first
// one that reads it to decide something rather than to keep it. Routing,
// normalization and detection arrive inside this loop; the loop is proven
// first, because everything after it depends on the position being correct.
type Engine struct {
	source  Source
	metrics *Metrics
	logger  *slog.Logger
	now     func() time.Time
}

func NewEngine(options EngineOptions) (*Engine, error) {
	switch {
	case options.Source == nil:
		return nil, errors.New("the analysis engine needs a source")
	case options.Metrics == nil:
		return nil, errors.New("the analysis engine needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the analysis engine needs a logger")
	}

	return &Engine{
		source:  options.Source,
		metrics: options.Metrics,
		logger:  options.Logger,
		now:     time.Now,
	}, nil
}

func (e *Engine) Name() string { return "analysis-engine" }

func (e *Engine) Run(ctx context.Context) error { return e.source.Consume(ctx, e.handle) }

// A record that cannot become an event is counted and reported, and the rest of
// the batch continues: one unreadable record must never hold a partition. Where
// it goes after that is a question of its own and is not answered here.
func (e *Engine) handle(ctx context.Context, records []Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.metrics.observeBatch(len(records))

	reached := e.now().UTC()
	analysed := 0
	for _, record := range records {
		decoded, err := e.decode(record)
		if err != nil {
			continue
		}
		e.metrics.observeDelay(reached, decoded)
		analysed++
	}

	e.metrics.analysed(analysed)
	return nil
}

func (e *Engine) decode(record Record) (*eventv1.Event, error) {
	var decoded eventv1.Event
	if err := proto.Unmarshal(record.Value, &decoded); err != nil {
		e.refuse(record, ReasonUndecodable, "the record is not a seagull.event.v1.Event")
		return nil, err
	}
	if err := event.ValidateContract(&decoded); err != nil {
		e.refuse(record, ReasonContractViolation, err.Error())
		return nil, err
	}
	return &decoded, nil
}

// The payload is never logged: it can carry attacker input, and the position is
// enough to fetch it from the backbone.
func (e *Engine) refuse(record Record, reason, detail string) {
	e.metrics.refused(reason)
	e.logger.Warn("event_not_analysable",
		slog.String("reason", reason),
		slog.String("detail", detail),
		slog.Int("partition", int(record.Partition)),
		slog.Int64("offset", record.Offset),
	)
}
