package analysis_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The whole suite runs on event time and never on the clock, which is what a
// controllable test clock amounts to here: nothing consults `time.Now`, so a
// window is moved by writing later events rather than by waiting.
var began = time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)

func threshold(t *testing.T, at int, within time.Duration, group ...detection.Field) *detection.Program {
	t.Helper()

	program, err := detection.Compile(detection.Rule{
		ID:          "ssh.repeated_failed_password",
		Revision:    3,
		Name:        "Repeated failed SSH passwords",
		Description: "More failed passwords from one address than an estate should see.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue("failure")},
		},
		Count:    detection.Count{AtLeast: at, Within: within, GroupBy: group},
		Severity: detection.High,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("compile a counting rule: %v", err)
	}
	return program
}

func failure(t *testing.T, at time.Time, source string) analysis.Record {
	t.Helper()

	record := fixtures.SSHAuthentication{
		EventID:  fmt.Sprintf("%s-%d", source, at.UnixNano()),
		SourceIP: source,
		At:       at,
	}.Event()

	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return analysis.Record{Partition: 0, Offset: at.Unix(), Value: payload}
}

func failures(t *testing.T, count int, apart time.Duration, source string) []analysis.Record {
	t.Helper()

	records := make([]analysis.Record, 0, count)
	for index := range count {
		records = append(records, failure(t, began.Add(time.Duration(index)*apart), source))
	}
	return records
}

func held(t *testing.T, bounds detectionstate.Bounds, program *detection.Program, records []analysis.Record) ([]*detectionv1.Detection, *metrics.Registry) {
	t.Helper()

	keeper, err := detectionstate.NewKeeper(bounds)
	if err != nil {
		t.Fatalf("bound the detection state: %v", err)
	}

	registry := metrics.New(t.Name())
	sink := &collected{}
	source := &oneBatch{records: records}
	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:         source,
		Rules:          pinned{id: "3538ec98f5ce3e22", programs: []*detection.Program{program}, held: true},
		State:          keeper,
		Detections:     sink,
		Metrics:        analysis.NewMetrics(registry),
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
	return sink.all(), registry
}

func bounded() detectionstate.Bounds {
	return detectionstate.Bounds{Window: time.Hour, ObservationsPerKey: 64, Keys: 16}
}

func TestARuleSaysNothingUntilItsThresholdIsReached(t *testing.T) {
	program := threshold(t, 20, time.Minute, "authentication.network.source.ip", "origin.agent_id")

	quiet, _ := held(t, bounded(), program, failures(t, 19, time.Second, "203.0.113.10"))
	if len(quiet) != 0 {
		t.Fatalf("nineteen failures made %d detections", len(quiet))
	}

	made, _ := held(t, bounded(), program, failures(t, 20, time.Second, "203.0.113.10"))
	if len(made) != 1 {
		t.Fatalf("twenty failures made %d detections", len(made))
	}

	counted := made[0].GetAggregation()
	if counted.GetCount() != 20 || counted.GetThreshold() != 20 {
		t.Errorf("the detection reports %d of %d", counted.GetCount(), counted.GetThreshold())
	}
	if counted.GetWindow().AsDuration() != time.Minute {
		t.Errorf("the detection reports a window of %s", counted.GetWindow().AsDuration())
	}
	if first := counted.GetFirstEventTime().AsTime(); !first.Equal(began) {
		t.Errorf("the window reaches back to %s and the first failure was at %s", first, began)
	}
	if made[0].GetEventTime().AsTime().Equal(began) {
		t.Error("the detection is placed at the first failure rather than at the one that crossed")
	}
}

func TestACountIsKeptApartByWhatTheRuleGroupsBy(t *testing.T) {
	program := threshold(t, 5, time.Minute, "authentication.network.source.ip")

	spread := append(failures(t, 4, time.Second, "203.0.113.10"), failures(t, 4, time.Second, "198.51.100.9")...)
	if made, _ := held(t, bounded(), program, spread); len(made) != 0 {
		t.Fatalf("eight failures from two addresses made %d detections", len(made))
	}

	var apart []analysis.Record
	for index := range 8 {
		apart = append(apart, failure(t, began.Add(time.Duration(index)*30*time.Second), "203.0.113.10"))
	}
	if made, _ := held(t, bounded(), program, apart); len(made) != 0 {
		t.Fatalf("eight failures spread over four minutes made %d detections", len(made))
	}
}

func TestADetectionReportsWhatTheEventsItCountedShared(t *testing.T) {
	program := threshold(t, 3, time.Minute, "authentication.network.source.ip", "origin.agent_id")

	made, _ := held(t, bounded(), program, failures(t, 3, time.Second, "203.0.113.10"))
	if len(made) != 1 {
		t.Fatalf("three failures made %d detections", len(made))
	}

	grouped := made[0].GetAggregation().GetGroup()
	if len(grouped) != 2 {
		t.Fatalf("the detection reports %d group fields", len(grouped))
	}
	if grouped[0].GetField() != "authentication.network.source.ip" || grouped[0].GetValue() != "203.0.113.10" {
		t.Errorf("the first group is %s=%q", grouped[0].GetField(), grouped[0].GetValue())
	}
	if grouped[1].GetField() != "origin.agent_id" || grouped[1].GetValue() != "dev-agent-01" {
		t.Errorf("the second group is %s=%q", grouped[1].GetField(), grouped[1].GetValue())
	}
}

func same(t *testing.T, one, other *detectionv1.Detection) bool {
	t.Helper()

	first, _ := proto.Clone(one).(*detectionv1.Detection)
	second, _ := proto.Clone(other).(*detectionv1.Detection)
	first.DetectedTime, second.DetectedTime = nil, nil
	return proto.Equal(first, second)
}

// Replay is the restart strategy rather than a case to survive: the same stream
// read again reaches the same counts and names the same detections, and the same
// batch delivered twice into one window adds nothing at all, because an event
// already folded moves neither the count nor what was decided from it.
func TestReplayingAStreamDecidesTheSameDetections(t *testing.T) {
	program := threshold(t, 5, time.Minute, "authentication.network.source.ip")
	records := failures(t, 7, time.Second, "203.0.113.10")

	first, _ := held(t, bounded(), program, records)
	second, _ := held(t, bounded(), program, records)
	if len(first) != len(second) {
		t.Fatalf("the same stream made %d detections and then %d", len(first), len(second))
	}
	for index := range first {
		if !same(t, first[index], second[index]) {
			t.Fatalf("the same stream decided %s and then %s differently", first[index].GetDetectionId(), second[index].GetDetectionId())
		}
	}

	twice, _ := held(t, bounded(), program, append(append([]analysis.Record{}, records...), records...))
	if len(twice) != len(first) {
		t.Fatalf("a redelivered batch made %d detections against %d", len(twice), len(first))
	}
	for index := range first {
		if !same(t, twice[index], first[index]) {
			t.Errorf("a redelivered batch rewrote %s differently", first[index].GetDetectionId())
		}
	}
}

// Nothing resets when a rule fires, so every event past the threshold decides
// again — one detection per matching event and never more, which is exactly what
// the same rule without a count would have produced from the first event on.
// Folding those into one piece of work is the alert plane's, under ADR 17.
func TestPastItsThresholdARuleDecidesOncePerEventAndNeverMore(t *testing.T) {
	program := threshold(t, 5, time.Minute, "authentication.network.source.ip")

	made, _ := held(t, bounded(), program, failures(t, 9, time.Second, "203.0.113.10"))
	if len(made) != 5 {
		t.Fatalf("nine failures past a threshold of five made %d detections", len(made))
	}

	named := make(map[string]struct{}, len(made))
	for index, one := range made {
		if count := one.GetAggregation().GetCount(); count != uint32(index+5) {
			t.Errorf("detection %d reports a count of %d", index, count)
		}
		if _, twice := named[one.GetDetectionId()]; twice {
			t.Errorf("%s was decided twice inside one stream", one.GetDetectionId())
		}
		named[one.GetDetectionId()] = struct{}{}
	}
}

func TestAWindowHoldsOnlyWhatIsStillInsideIt(t *testing.T) {
	program := threshold(t, 3, 10*time.Second, "authentication.network.source.ip")

	var trickle []analysis.Record
	for index := range 10 {
		trickle = append(trickle, failure(t, began.Add(time.Duration(index)*time.Minute), "203.0.113.10"))
	}
	if made, _ := held(t, bounded(), program, trickle); len(made) != 0 {
		t.Fatalf("ten failures a minute apart inside a ten-second window made %d detections", len(made))
	}

	burst := []analysis.Record{
		failure(t, began, "203.0.113.10"),
		failure(t, began.Add(time.Hour), "203.0.113.10"),
		failure(t, began.Add(time.Hour+time.Second), "203.0.113.10"),
		failure(t, began.Add(time.Hour+2*time.Second), "203.0.113.10"),
	}
	made, _ := held(t, bounded(), program, burst)
	if len(made) != 1 {
		t.Fatalf("a burst after a long quiet period made %d detections", len(made))
	}
	if count := made[0].GetAggregation().GetCount(); count != 3 {
		t.Errorf("the burst was counted as %d, so the failure an hour earlier is still inside the window", count)
	}
}

// A store at its key ceiling refuses a new key rather than evicting one, so a
// flood of invented group values cannot choose which real counts an estate
// forgets. The refusal is answered and counted rather than swallowed.
func TestAFloodOfGroupsIsRefusedAndCounted(t *testing.T) {
	program := threshold(t, 2, time.Minute, "authentication.network.source.ip")
	bounds := detectionstate.Bounds{Window: time.Hour, ObservationsPerKey: 8, Keys: 2}

	var flood []analysis.Record
	for index := range 8 {
		address := fmt.Sprintf("203.0.113.%d", index)
		flood = append(flood, failure(t, began.Add(time.Duration(index)*time.Second), address))
	}

	_, registry := held(t, bounds, program, flood)
	body := exposition(t, registry)
	if !strings.Contains(body, `seagull_detection_state_observations_total{outcome="at_capacity"}`) {
		t.Fatalf("a store that refused a key counted nothing: %s", body)
	}
	if !strings.Contains(body, `seagull_detection_state_observations_total{outcome="counted"}`) {
		t.Errorf("the observations that were taken were not counted: %s", body)
	}
}

func TestASaturatedKeyIsCountedAndSaidSo(t *testing.T) {
	program := threshold(t, 3, time.Minute, "authentication.network.source.ip")
	bounds := detectionstate.Bounds{Window: time.Hour, ObservationsPerKey: 4, Keys: 4}

	made, registry := held(t, bounds, program, failures(t, 8, time.Second, "203.0.113.10"))
	if len(made) == 0 {
		t.Fatal("eight failures past a threshold of three made nothing")
	}
	if last := made[len(made)-1].GetAggregation(); !last.GetSaturated() || last.GetCount() != 4 {
		t.Errorf("a key bounded to four observations reported %d and saturated=%v", last.GetCount(), last.GetSaturated())
	}
	if body := exposition(t, registry); !strings.Contains(body, "seagull_detection_state_saturated_total") {
		t.Errorf("a saturated key was not counted: %s", body)
	}
}

func TestTheKeysAStoreHoldsAreReportedAgainstItsCeiling(t *testing.T) {
	keeper, err := detectionstate.NewKeeper(bounded())
	if err != nil {
		t.Fatalf("bound the detection state: %v", err)
	}

	registry := metrics.New(t.Name())
	analysis.ObserveState(registry, bounded(), keeper.Keys)

	body := exposition(t, registry)
	for _, expected := range []string{"seagull_detection_state_keys 0", "seagull_detection_state_key_ceiling 16"} {
		if !strings.Contains(body, expected) {
			t.Errorf("%q is missing from the exposition: %s", expected, body)
		}
	}
}
