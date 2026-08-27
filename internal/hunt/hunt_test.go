package hunt_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

type store struct {
	events     []*eventv1.Event
	detections []*detectionv1.Detection
	err        error
	linger     time.Duration
	seen       hunt.Query
}

func (s *store) Events(ctx context.Context, query hunt.Query) ([]*eventv1.Event, error) {
	s.seen = query
	return s.events, s.wait(ctx)
}

func (s *store) Detections(ctx context.Context, query hunt.Query) ([]*detectionv1.Detection, error) {
	s.seen = query
	return s.detections, s.wait(ctx)
}

func (s *store) wait(ctx context.Context) error {
	if s.linger == 0 {
		return s.err
	}
	select {
	case <-time.After(s.linger):
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func stored(id string, at time.Time) *eventv1.Event {
	return &eventv1.Event{
		EventId:    id,
		EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Time:       &eventv1.Timestamps{EventTime: timestamppb.New(at)},
	}
}

func hunter(t *testing.T, source hunt.Source) *hunt.Hunter {
	t.Helper()

	built, err := hunt.NewHunter(hunt.HunterOptions{
		Source:   source,
		Compiler: compiler(t),
		Metrics:  hunt.NewMetrics(metrics.New("test")),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("build the hunter: %v", err)
	}
	return built
}

// A page that carried anything is followed by a cursor, and only the empty page
// says the range is exhausted: a store answers within a budget, so a short page
// is not proof there is nothing more.
func TestAPageThatCarriedSomethingIsFollowedByACursor(t *testing.T) {
	source := &store{events: []*eventv1.Event{stored("aaaa", day), stored("bbbb", day.Add(-time.Minute))}}

	page, err := hunter(t, source).Events(context.Background(), scoped(t, "acme"), asked(nil))
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	if len(page.GetEvents()) != 2 {
		t.Fatalf("the page carried %d events", len(page.GetEvents()))
	}
	if page.GetNextCursor() == "" {
		t.Error("a page carrying records ended the answer")
	}
}

func TestAnEmptyPageEndsTheAnswer(t *testing.T) {
	page, err := hunter(t, &store{}).Events(context.Background(), scoped(t, "acme"), asked(nil))
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	if page.GetNextCursor() != "" {
		t.Error("an empty page offered somewhere to carry on from")
	}
}

// The cursor resumes at the last record of the page, which is the pair the store
// is sorted by, so the next page starts where this one stopped rather than a
// count of records later.
func TestTheCursorResumesAtTheLastRecord(t *testing.T) {
	last := day.Add(-time.Minute)
	source := &store{events: []*eventv1.Event{stored("aaaa", day), stored("bbbb", last)}}
	built := hunter(t, source)

	page, err := built.Events(context.Background(), scoped(t, "acme"), asked(nil))
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}

	if _, err := built.Events(context.Background(), scoped(t, "acme"),
		&huntv1.Query{Range: window(time.Hour), Cursor: page.GetNextCursor()}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	after := source.seen.After()
	if !after.Set || after.ID != "bbbb" || !after.Time.Equal(last) {
		t.Errorf("the store was asked to carry on from %+v", after)
	}
}

func TestTheReadBudgetIsADeadlineAsWellAsASetting(t *testing.T) {
	source := &store{linger: time.Minute}
	built, err := hunt.NewHunter(hunt.HunterOptions{
		Source: source,
		Compiler: func() *hunt.Compiler {
			narrow := limits()
			narrow.Timeout = 50 * time.Millisecond
			built, err := hunt.NewCompiler(hunt.CompilerOptions{Limits: narrow, CursorKey: make([]byte, 32)})
			if err != nil {
				t.Fatalf("build the compiler: %v", err)
			}
			return built
		}(),
		Metrics: hunt.NewMetrics(metrics.New("slow")),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("build the hunter: %v", err)
	}

	started := time.Now()
	if _, err := built.Events(context.Background(), scoped(t, "acme"), asked(nil)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a store that never answered produced %v", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Errorf("the caller waited %s for a store that was given 50ms", elapsed)
	}
}

func TestAStoreThatRefusedIsNotAQueryThatWasWrong(t *testing.T) {
	source := &store{err: errors.New("the store is unreachable")}

	_, err := hunter(t, source).Detections(context.Background(), scoped(t, "acme"), asked(nil))
	if err == nil {
		t.Fatal("a store that failed answered")
	}
	var refusal *hunt.Refusal
	if errors.As(err, &refusal) {
		t.Errorf("a store failure was reported as a bad query: %v", refusal)
	}
}

func TestTheStoreIsAskedForTheScopeAndTheWindowItWasGiven(t *testing.T) {
	source := &store{}

	if _, err := hunter(t, source).Events(context.Background(), scoped(t, "acme"), asked(nil)); err != nil {
		t.Fatalf("hunt: %v", err)
	}
	if tenants := source.seen.Scope().Tenants(); len(tenants) != 1 || tenants[0] != "acme" {
		t.Errorf("the store was asked for %v", tenants)
	}
	if width := source.seen.Range().Width(); width != time.Hour {
		t.Errorf("the store was asked about %s", width)
	}
}

func TestAHunterNeedsAStoreACompilerAndMetrics(t *testing.T) {
	if _, err := hunt.NewHunter(hunt.HunterOptions{Compiler: compiler(t), Metrics: hunt.NewMetrics(metrics.New("bare"))}); err == nil {
		t.Error("a hunter was built with no store")
	}
	if _, err := hunt.NewHunter(hunt.HunterOptions{Source: &store{}, Metrics: hunt.NewMetrics(metrics.New("bare2"))}); err == nil {
		t.Error("a hunter was built with nothing to hold a query to its limits")
	}
}
