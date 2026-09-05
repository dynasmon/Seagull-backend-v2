package analysis_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

// Every process gets its own keeper: state held in a process is exactly what a
// crash takes away.
func process(t *testing.T, program *detection.Program, records []analysis.Record) []*detectionv1.Detection {
	t.Helper()

	keeper, err := detectionstate.NewKeeper(bounded())
	if err != nil {
		t.Fatalf("bound the detection state: %v", err)
	}

	sink := &collected{}
	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:         &oneBatch{records: records},
		Rules:          pinned{id: "3538ec98f5ce3e22", programs: []*detection.Program{program}, held: true},
		State:          keeper,
		Detections:     sink,
		Metrics:        analysis.NewMetrics(metrics.New(t.Name())),
		Logger:         slog.New(slog.NewJSONHandler(&strings.Builder{}, &slog.HandlerOptions{Level: slog.LevelWarn})),
		PublishTimeout: 5 * time.Second,
		RetryDelay:     time.Millisecond,
		MaxRetryDelay:  10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}
	return sink.all()
}

func names(made []*detectionv1.Detection) []string {
	found := make([]string, 0, len(made))
	for _, one := range made {
		found = append(found, one.GetDetectionId())
	}
	return found
}

func brute(t *testing.T) (*detection.Program, []analysis.Record) {
	t.Helper()

	return threshold(t, 20, 10*time.Minute, "authentication.network.source.ip", "origin.agent_id"),
		failures(t, 20, 30*time.Second, "203.0.113.10")
}

// The invariant this whole wave is about: a process that read back over the
// window it was in the middle of decides what a process that never stopped
// would have decided, down to the name of the detection.
func TestAProcessThatReadBackOverItsWindowDecidesWhatOneThatNeverStoppedDid(t *testing.T) {
	program, records := brute(t)

	unbroken := process(t, program, records)
	if len(unbroken) != 1 {
		t.Fatalf("twenty failures in one process made %d detections", len(unbroken))
	}

	crashed := process(t, program, records[:15])
	if len(crashed) != 0 {
		t.Fatalf("fifteen failures made %d detections before the crash", len(crashed))
	}

	recovered := process(t, program, records)
	if len(recovered) != 1 {
		t.Fatalf("a process that read the window back made %d detections", len(recovered))
	}
	if names(recovered)[0] != names(unbroken)[0] {
		t.Errorf("recovery decided %s and an unbroken process decided %s",
			names(recovered)[0], names(unbroken)[0])
	}
}

// The failure the recovery removes: twenty events inside the window read as
// five, because the process resumed at the committed position.
func TestAProcessThatResumesWithoutItsWindowFindsNothing(t *testing.T) {
	program, records := brute(t)

	if resumed := process(t, program, records[15:]); len(resumed) != 0 {
		t.Fatalf("five failures alone made %d detections, so this test proves nothing", len(resumed))
	}
}

// Reading the window back re-decides events, which is safe because a window
// refuses to count an event it already holds.
func TestReadingTheWindowBackDecidesTheSameDetectionAndNotASecondOne(t *testing.T) {
	program, records := brute(t)

	twice := process(t, program, append(append([]analysis.Record{}, records...), records...))
	if len(twice) != 1 {
		t.Fatalf("the same twenty failures delivered twice made %d detections: %v", len(twice), names(twice))
	}
	if twice[0].GetDetectionId() != names(process(t, program, records))[0] {
		t.Error("a redelivered stream decided a different detection from the one it decided first")
	}
}

func TestASequenceIsFoundAgainByTheProcessThatReadItsWindowBack(t *testing.T) {
	program := story(t, 5*time.Minute, "authentication.network.source.ip", "origin.agent_id")
	records := []analysis.Record{
		failed(t, 0),
		failed(t, 30*time.Second),
		failed(t, time.Minute),
		accepted(t, 2*time.Minute),
	}

	unbroken := process(t, program, records)
	if len(unbroken) != 1 {
		t.Fatalf("a completed story in one process made %d detections", len(unbroken))
	}

	crashed := process(t, program, records[:3])
	if len(crashed) != 0 {
		t.Fatalf("the failures alone made %d detections", len(crashed))
	}

	if resumed := process(t, program, records[3:]); len(resumed) != 0 {
		t.Fatalf("the success alone made %d detections, so this test proves nothing", len(resumed))
	}

	recovered := process(t, program, records)
	if len(recovered) != 1 || names(recovered)[0] != names(unbroken)[0] {
		t.Errorf("recovery decided %v and an unbroken process decided %v",
			names(recovered), names(unbroken))
	}
}

// A ruleset arriving mid-window has defined transition semantics, and they come
// from the state key rather than from anything the swap does: an unchanged rule
// keeps its window, and a revised one asks a different question and starts a
// window of its own.
func TestARulesetSwapKeepsWhatAnUnchangedRuleCountedAndRestartsARevisedOne(t *testing.T) {
	first := threshold(t, 20, 10*time.Minute, "authentication.network.source.ip", "origin.agent_id")
	records := failures(t, 20, 30*time.Second, "203.0.113.10")

	keeper, err := detectionstate.NewKeeper(bounded())
	if err != nil {
		t.Fatalf("bound the detection state: %v", err)
	}

	unchanged := decidedBy(t, keeper, first, records[:15])
	if len(unchanged) != 0 {
		t.Fatalf("fifteen failures made %d detections", len(unchanged))
	}
	if made := decidedBy(t, keeper, first, records[15:]); len(made) != 1 {
		t.Fatalf("a ruleset that did not change the rule made %d detections from the rest", len(made))
	}

	revised := revision(t, first, 4)
	if made := decidedBy(t, keeper, revised, records[15:]); len(made) != 0 {
		t.Fatalf("a revised rule inherited the window of the one it replaced: %v", names(made))
	}
}

// One store across two rulesets, which is what a swap actually is: the process
// keeps the state it had and reads the next event against something else.
func decidedBy(t *testing.T, keeper *detectionstate.Keeper, program *detection.Program, records []analysis.Record) []*detectionv1.Detection {
	t.Helper()

	sink := &collected{}
	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:         &oneBatch{records: records},
		Rules:          pinned{id: "3538ec98f5ce3e22", programs: []*detection.Program{program}, held: true},
		State:          keeper,
		Detections:     sink,
		Metrics:        analysis.NewMetrics(metrics.New(t.Name() + string(program.Rule().ID))),
		Logger:         slog.New(slog.NewJSONHandler(&strings.Builder{}, &slog.HandlerOptions{Level: slog.LevelWarn})),
		PublishTimeout: 5 * time.Second,
		RetryDelay:     time.Millisecond,
		MaxRetryDelay:  10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}
	return sink.all()
}

func revision(t *testing.T, program *detection.Program, at int) *detection.Program {
	t.Helper()

	rule := program.Rule()
	rule.Revision = at
	revised, err := detection.Compile(rule)
	if err != nil {
		t.Fatalf("compile a revision of the rule: %v", err)
	}
	return revised
}
