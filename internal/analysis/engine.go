package analysis

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
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
	Source     Source
	Rules      Rules
	Detections Detections
	Metrics    *Metrics
	Logger     *slog.Logger

	PublishTimeout time.Duration
	RetryDelay     time.Duration
	MaxRetryDelay  time.Duration
}

// The second consumer of the raw telemetry the gateway admitted, and the first
// one that reads it to decide something rather than to keep it. It routes an
// event by its class, puts it into the canonical form that class defines,
// decides it against the rules registered on that route, and puts what it found
// back on the backbone for somebody else to keep.
type Engine struct {
	source     Source
	rules      Rules
	detections Detections
	metrics    *Metrics
	logger     *slog.Logger
	now        func() time.Time

	publishTimeout time.Duration
	retryDelay     time.Duration
	maxRetryDelay  time.Duration
}

func NewEngine(options EngineOptions) (*Engine, error) {
	switch {
	case options.Source == nil:
		return nil, errors.New("the analysis engine needs a source")
	case options.Rules == nil:
		return nil, errors.New("the analysis engine needs rules")
	case options.Detections == nil:
		return nil, errors.New("the analysis engine needs somewhere to put what it finds")
	case options.Metrics == nil:
		return nil, errors.New("the analysis engine needs metrics")
	case options.Logger == nil:
		return nil, errors.New("the analysis engine needs a logger")
	case options.PublishTimeout <= 0:
		return nil, errors.New("the analysis engine needs a positive publish budget")
	case options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the analysis engine needs a retry delay below its ceiling")
	}

	return &Engine{
		source:         options.Source,
		rules:          options.Rules,
		detections:     options.Detections,
		metrics:        options.Metrics,
		logger:         options.Logger,
		now:            time.Now,
		publishTimeout: options.PublishTimeout,
		retryDelay:     options.RetryDelay,
		maxRetryDelay:  options.MaxRetryDelay,
	}, nil
}

func (e *Engine) Name() string { return "analysis-engine" }

func (e *Engine) Run(ctx context.Context) error { return e.source.Consume(ctx, e.handle) }

// A record that cannot become an event is counted and reported, and the rest of
// the batch continues: one unreadable record must never hold a partition. Where
// it goes after that is a question of its own and is not answered here.
//
// What the batch was found to be is published before this returns, and the group
// position advances only after it does. A crash between the two replays the
// batch and decides it again, which writes the same detections under the same
// names rather than a second set of them.
//
// The whole batch shares one decision time: it is when the engine reached these
// records, it is what a detection reports as the moment it was decided, and it
// is deliberately no part of how a detection is named.
func (e *Engine) handle(ctx context.Context, records []Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.metrics.observeBatch(len(records))

	reached := e.now().UTC()
	analysed := 0
	var made []*detectionv1.Detection
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
		made = append(made, e.detect(decoded, stage.Route, record, reached)...)
		analysed++
	}

	e.metrics.analysed(analysed)
	return e.publish(ctx, made)
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
