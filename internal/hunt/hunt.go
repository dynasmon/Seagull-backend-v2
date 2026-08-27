package hunt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

// What the query plane needs of a store: one page of records, newest first,
// within the scope, the window and the budget the query already carries. The
// store is asked; it is not consulted about who may ask.
type Source interface {
	Events(ctx context.Context, query Query) ([]*eventv1.Event, error)
	Detections(ctx context.Context, query Query) ([]*detectionv1.Detection, error)
}

type HunterOptions struct {
	Source   Source
	Compiler *Compiler
	Metrics  *Metrics
	Logger   *slog.Logger
}

type Hunter struct {
	source   Source
	compiler *Compiler
	metrics  *Metrics
	logger   *slog.Logger
}

func NewHunter(options HunterOptions) (*Hunter, error) {
	switch {
	case options.Source == nil:
		return nil, errors.New("a hunt needs a store to ask")
	case options.Compiler == nil:
		return nil, errors.New("a hunt needs a compiler to hold a question to its limits")
	case options.Metrics == nil:
		return nil, errors.New("a hunt needs metrics")
	}

	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Hunter{source: options.Source, compiler: options.Compiler, metrics: options.Metrics, logger: logger}, nil
}

func (h *Hunter) Events(ctx context.Context, scope Scope, asked *huntv1.Query) (*huntv1.EventPage, error) {
	query, err := h.compiler.Compile(Events, scope, asked)
	if err != nil {
		return nil, h.refused(Events, err)
	}

	records, elapsed, err := answer(ctx, query, h.source.Events)
	if err != nil {
		h.metrics.failed(Events, elapsed)
		return nil, err
	}

	h.observe(query, len(records), elapsed)
	page := &huntv1.EventPage{Events: records}
	if last := len(records) - 1; last >= 0 {
		page.NextCursor = h.compiler.Next(query,
			records[last].GetTime().GetEventTime().AsTime(), records[last].GetEventId())
	}
	return page, nil
}

func (h *Hunter) Detections(ctx context.Context, scope Scope, asked *huntv1.Query) (*huntv1.DetectionPage, error) {
	query, err := h.compiler.Compile(Detections, scope, asked)
	if err != nil {
		return nil, h.refused(Detections, err)
	}

	records, elapsed, err := answer(ctx, query, h.source.Detections)
	if err != nil {
		h.metrics.failed(Detections, elapsed)
		return nil, err
	}

	h.observe(query, len(records), elapsed)
	page := &huntv1.DetectionPage{Detections: records}
	if last := len(records) - 1; last >= 0 {
		page.NextCursor = h.compiler.Next(query,
			records[last].GetEventTime().AsTime(), records[last].GetDetectionId())
	}
	return page, nil
}

// The read budget is a deadline as well as a setting the store is asked to
// honour, so a source that ignores its own limit still cannot hold a caller
// open indefinitely.
func answer[T any](ctx context.Context, query Query, read func(context.Context, Query) ([]T, error)) ([]T, time.Duration, error) {
	bounded, cancel := context.WithTimeout(ctx, query.Timeout())
	defer cancel()

	started := time.Now()
	records, err := read(bounded, query)
	elapsed := time.Since(started)
	if err != nil {
		return nil, elapsed, fmt.Errorf("answer a %s query: %w", query.Dataset(), err)
	}
	return records, elapsed, nil
}

// A page is followed by a cursor whenever it carried anything at all, and by
// nothing when it did not. A short page is not proof that the range is
// exhausted — a store answers within a budget — so the empty page is what says
// so, at the cost of one more round trip.
func (h *Hunter) observe(query Query, records int, elapsed time.Duration) {
	h.metrics.answered(query.Dataset(), records, elapsed)
	h.logger.Info("hunt_answered",
		slog.String("dataset", string(query.Dataset())),
		slog.Int("records", records),
		slog.Duration("window", query.Range().Width()),
		slog.Duration("elapsed", elapsed),
	)
}

func (h *Hunter) refused(dataset Dataset, err error) error {
	reason := "invalid_query"
	var refusal *Refusal
	if errors.As(err, &refusal) {
		reason = refusal.Code
	}
	h.metrics.refused(dataset, reason)
	return err
}
