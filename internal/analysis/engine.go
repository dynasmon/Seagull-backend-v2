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
	Rules   Rules
	Metrics *Metrics
	Logger  *slog.Logger
}

// The second consumer of the raw telemetry the gateway admitted, and the first
// one that reads it to decide something rather than to keep it. It routes an
// event by its class, puts it into the canonical form that class defines, and
// decides it against the rules registered on that route.
type Engine struct {
	source  Source
	rules   Rules
	metrics *Metrics
	logger  *slog.Logger
	now     func() time.Time
}

func NewEngine(options EngineOptions) (*Engine, error) {
	switch {
	case options.Source == nil:
		return nil, errors.New("the analysis engine needs a source")
	case options.Rules == nil:
		return nil, errors.New("the analysis engine needs rules")
	case options.Metrics == nil:
		return nil, errors.New("the analysis engine needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the analysis engine needs a logger")
	}

	return &Engine{
		source:  options.Source,
		rules:   options.Rules,
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
		decoded, stage, readable := e.read(record)
		if !readable {
			continue
		}
		if stage.Normalize(decoded) {
			e.metrics.normalized(stage.Route)
		}
		e.metrics.observeDelay(reached, decoded)
		e.metrics.routed(stage.Route)
		e.detect(decoded, stage.Route, record)
		analysed++
	}

	e.metrics.analysed(analysed)
	return nil
}

// A record becomes an event, and the event's class decides what runs on it.
func (e *Engine) read(record Record) (*eventv1.Event, Stage, bool) {
	var decoded eventv1.Event
	if err := proto.Unmarshal(record.Value, &decoded); err != nil {
		e.refuse(record, ReasonUndecodable, "the record is not a seagull.event.v1.Event")
		return nil, Stage{}, false
	}

	// A class this build's contract has never heard of is not a malformed
	// record: the gateway validated the class before it admitted the event, so
	// the stream has moved ahead of the process reading it and the answer is a
	// deployment. Holding it to a contract that does not know the class would
	// say the opposite, and blame a producer that is doing nothing wrong.
	class := decoded.GetEventClass()
	if !Declared(class) {
		e.unrouted(record, class)
		return nil, Stage{}, false
	}

	if err := event.ValidateContract(&decoded); err != nil {
		e.refuse(record, ReasonContractViolation, err.Error())
		return nil, Stage{}, false
	}

	// Everything the contract declares and admits has a stage: the suite holds
	// the routing table and the contract together, and a class that reaches
	// here without one means they have drifted apart.
	stage, routed := StageFor(class)
	if !routed {
		e.unrouted(record, class)
		return nil, Stage{}, false
	}
	return &decoded, stage, true
}

// Reported by class rather than by payload, and counted apart from a refusal,
// because an operator answers the two differently: one is a deployment, the
// other is a producer to go and find.
func (e *Engine) unrouted(record Record, class eventv1.EventClass) {
	name := ClassName(class)
	e.metrics.unroutable(name)
	e.logger.Warn("event_not_routed",
		slog.String("class", name),
		slog.Int("partition", int(record.Partition)),
		slog.Int64("offset", record.Offset),
	)
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
