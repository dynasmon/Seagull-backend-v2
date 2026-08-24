package analysis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// One batch, then the source reports it is done, which is how the engine's loop
// is driven without a broker.
type oneBatch struct {
	records  []analysis.Record
	handled  int
	delivery error
}

func (o *oneBatch) Consume(ctx context.Context, deliver analysis.Deliver) error {
	o.handled++
	o.delivery = deliver(ctx, o.records)
	return o.delivery
}

type blockingSource struct{ entered chan struct{} }

func (b blockingSource) Consume(ctx context.Context, _ analysis.Deliver) error {
	close(b.entered)
	<-ctx.Done()
	return ctx.Err()
}

func admitted(t *testing.T, eventID string) []byte {
	t.Helper()

	record := fixtures.SSHAuthentication{EventID: eventID}.Event()
	record.Reception = &eventv1.Reception{
		IngestTime: timestamppb.New(time.Now().UTC()),
		Gateway:    "gateway-a",
		BatchId:    "batch-a",
	}
	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return payload
}

func withoutIdentity(t *testing.T) []byte {
	t.Helper()

	record := fixtures.SSHAuthentication{}.Event()
	record.EventId = ""
	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return payload
}

// The ruleset the test pins the engine to, in place of the registry an
// executable wires in. One type answers both halves of the seam, because a test
// has nothing to reload.
type pinned struct {
	id       string
	programs []*detection.Program
	held     bool
}

func (p pinned) Current() analysis.Ruleset {
	if !p.held {
		return nil
	}
	return p
}

func (p pinned) ID() string { return p.id }

func (p pinned) For(class eventv1.EventClass) iter.Seq[*detection.Program] {
	return func(yield func(*detection.Program) bool) {
		for _, program := range p.programs {
			if program.Rule().Class != class {
				continue
			}
			if !yield(program) {
				return
			}
		}
	}
}

func nothingToRun() pinned { return pinned{id: "e3b0c44298fc1c14", held: true} }

// A rule that decides the event the fixture produces, and one that decides the
// same event the other way, so a batch exercises both answers.
func compiled(t *testing.T, id string, outcome string) *detection.Program {
	t.Helper()

	program, err := detection.Compile(detection.Rule{
		ID:          detection.ID(id),
		Revision:    3,
		Name:        "Authentication ended a particular way",
		Description: "A rule narrow enough to be decided from one event.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue(outcome)},
		},
		Severity: detection.High,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("compile rule %q: %v", id, err)
	}
	return program
}

func newEngine(t *testing.T, source analysis.Source) (*analysis.Engine, *bytes.Buffer, *metrics.Registry) {
	t.Helper()
	return engineOn(t, source, nothingToRun(), slog.LevelWarn)
}

func engineOn(t *testing.T, source analysis.Source, rules analysis.Rules, level slog.Level) (*analysis.Engine, *bytes.Buffer, *metrics.Registry) {
	t.Helper()

	var written bytes.Buffer
	registry := metrics.New("test")
	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:  source,
		Rules:   rules,
		Metrics: analysis.NewMetrics(registry),
		Logger:  slog.New(slog.NewJSONHandler(&written, &slog.HandlerOptions{Level: level})),
	})
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return engine, &written, registry
}

// What the process would answer on its operational listener, which is where an
// operator reads any of this.
func exposition(t *testing.T, registry *metrics.Registry) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("the metrics endpoint answered %d", recorder.Code)
	}
	return recorder.Body.String()
}

// An event carrying a class this build's contract does not declare, which is
// what a producer running ahead of this process publishes.
func fromANewerContract(t *testing.T) []byte {
	t.Helper()

	record := fixtures.SSHAuthentication{EventID: "event-from-a-newer-contract"}.Event()
	record.EventClass = eventv1.EventClass(4242)
	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return payload
}

// The same event a collector produces when it copies what a log line said
// rather than what the platform matches on.
func inANonCanonicalForm(t *testing.T) []byte {
	t.Helper()

	record := fixtures.SSHAuthentication{
		EventID:  "event-in-a-non-canonical-form",
		Hostname: "WEB-01.",
		SourceIP: "::ffff:203.0.113.10",
		Method:   "PASSWORD",
	}.Event()
	record.Reception = &eventv1.Reception{
		IngestTime: timestamppb.New(time.Now().UTC()),
		Gateway:    "gateway-a",
		BatchId:    "batch-a",
	}
	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return payload
}

func withoutAClass(t *testing.T) []byte {
	t.Helper()

	record := fixtures.SSHAuthentication{EventID: "event-without-a-class"}.Event()
	record.EventClass = eventv1.EventClass_EVENT_CLASS_UNSPECIFIED
	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return payload
}

func entries(t *testing.T, written *bytes.Buffer) []map[string]any {
	t.Helper()

	var decoded []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(written.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode log entry: %v", err)
		}
		decoded = append(decoded, entry)
	}
	return decoded
}

func TestAWellFormedBatchIsAnalysedWithoutComplaint(t *testing.T) {
	source := &oneBatch{records: []analysis.Record{
		{Partition: 0, Offset: 1, Value: admitted(t, "event-one")},
		{Partition: 0, Offset: 2, Value: admitted(t, "event-two")},
	}}
	engine, written, _ := newEngine(t, source)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}
	if source.handled != 1 {
		t.Errorf("the source was driven %d times", source.handled)
	}
	if source.delivery != nil {
		t.Errorf("the batch was refused: %v", source.delivery)
	}
	if reported := entries(t, written); len(reported) != 0 {
		t.Errorf("a well formed batch was reported: %v", reported)
	}
}

// The engine must not return an error for a record it cannot read, or the
// source would never advance and one bad record would hold the partition.
func TestAnUnreadableRecordDoesNotHoldTheBatch(t *testing.T) {
	poison := []byte("this is not a protobuf message at all")
	source := &oneBatch{records: []analysis.Record{
		{Partition: 3, Offset: 41, Value: poison},
		{Partition: 3, Offset: 42, Value: admitted(t, "event-after-the-poison")},
	}}
	engine, written, _ := newEngine(t, source)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}
	if source.delivery != nil {
		t.Fatalf("one unreadable record refused the whole batch: %v", source.delivery)
	}

	reported := entries(t, written)
	if len(reported) != 1 {
		t.Fatalf("expected one refusal and got %d: %v", len(reported), reported)
	}
	if reason := reported[0]["reason"]; reason != analysis.ReasonUndecodable {
		t.Errorf("the refusal reads %q and should read %q", reason, analysis.ReasonUndecodable)
	}
	if partition, offset := reported[0]["partition"], reported[0]["offset"]; partition != 3.0 || offset != 41.0 {
		t.Errorf("the refusal points at partition %v offset %v", partition, offset)
	}
	if strings.Contains(written.String(), string(poison)) {
		t.Error("the refused payload reached the log")
	}
}

func TestARecordThatBreaksTheContractIsRefusedByReason(t *testing.T) {
	source := &oneBatch{records: []analysis.Record{
		{Partition: 1, Offset: 7, Value: withoutIdentity(t)},
	}}
	engine, written, _ := newEngine(t, source)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}

	reported := entries(t, written)
	if len(reported) != 1 {
		t.Fatalf("expected one refusal and got %d", len(reported))
	}
	if reason := reported[0]["reason"]; reason != analysis.ReasonContractViolation {
		t.Errorf("the refusal reads %q and should read %q", reason, analysis.ReasonContractViolation)
	}
	if detail, _ := reported[0]["detail"].(string); !strings.Contains(detail, "event_id") {
		t.Errorf("the refusal does not name the field that broke: %q", detail)
	}
}

func TestTheEngineStopsWhenItsContextIsCancelled(t *testing.T) {
	source := blockingSource{entered: make(chan struct{})}
	engine, _, _ := newEngine(t, source)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- engine.Run(ctx) }()

	<-source.entered
	cancel()

	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the engine stopped with %v and should stop cancelled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the engine did not stop when its context was cancelled")
	}
}

func TestTheEngineRefusesToStartWithoutWhatItNeeds(t *testing.T) {
	registry := metrics.New("test")
	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))

	missing := map[string]analysis.EngineOptions{
		"no source":  {Rules: nothingToRun(), Metrics: analysis.NewMetrics(registry), Logger: logger},
		"no rules":   {Source: &oneBatch{}, Metrics: analysis.NewMetrics(metrics.New("without-rules")), Logger: logger},
		"no metrics": {Source: &oneBatch{}, Rules: nothingToRun(), Logger: logger},
		"no logger":  {Source: &oneBatch{}, Rules: nothingToRun(), Metrics: analysis.NewMetrics(metrics.New("other"))},
	}
	for name, options := range missing {
		t.Run(name, func(t *testing.T) {
			if _, err := analysis.NewEngine(options); err == nil {
				t.Error("the engine started without a dependency it needs")
			}
		})
	}
}

func TestAnEventIsCountedUnderTheRouteItsClassSendsItDown(t *testing.T) {
	source := &oneBatch{records: []analysis.Record{
		{Partition: 0, Offset: 1, Value: admitted(t, "event-one")},
		{Partition: 0, Offset: 2, Value: admitted(t, "event-two")},
	}}
	engine, _, registry := newEngine(t, source)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}

	body := exposition(t, registry)
	if !strings.Contains(body, `seagull_analysis_routed_total{route="authentication"} 2`) {
		t.Errorf("the engine did not count both events under their route:\n%s", body)
	}
}

// The version-skew case, and the reason routing decides before the contract
// does: an older engine must report a class it does not know as its own gap,
// not as a broken producer.
func TestAClassFromANewerContractIsReportedRatherThanRefused(t *testing.T) {
	source := &oneBatch{records: []analysis.Record{
		{Partition: 2, Offset: 9, Value: fromANewerContract(t)},
		{Partition: 2, Offset: 10, Value: admitted(t, "event-this-build-knows")},
	}}
	engine, written, registry := newEngine(t, source)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}
	if source.delivery != nil {
		t.Fatalf("a class this build does not route refused the whole batch: %v", source.delivery)
	}

	reported := entries(t, written)
	if len(reported) != 1 {
		t.Fatalf("expected one report and got %d: %v", len(reported), reported)
	}
	if message := reported[0]["msg"]; message != "event_not_routed" {
		t.Errorf("the report reads %q and should read %q", message, "event_not_routed")
	}
	if class := reported[0]["class"]; class != "unknown" {
		t.Errorf("the class is reported as %q, which the exposition cannot bound", class)
	}
	if partition, offset := reported[0]["partition"], reported[0]["offset"]; partition != 2.0 || offset != 9.0 {
		t.Errorf("the report points at partition %v offset %v", partition, offset)
	}

	body := exposition(t, registry)
	for _, expected := range []string{
		`seagull_analysis_unrouted_total{class="unknown"} 1`,
		`seagull_analysis_events_total{outcome="unrouted"} 1`,
		`seagull_analysis_routed_total{route="authentication"} 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("%s missing from the exposition:\n%s", expected, body)
		}
	}
	if strings.Contains(body, "seagull_analysis_refusals_total") {
		t.Error("a class this build does not route was counted as a refusal")
	}
}

// The other side of that line: a producer that says nothing about what it sent
// is broken, and the contract refuses it by name rather than the engine
// filing it under a class it might learn about later.
func TestAnEventThatDoesNotSayWhatItIsIsRefused(t *testing.T) {
	source := &oneBatch{records: []analysis.Record{
		{Partition: 5, Offset: 3, Value: withoutAClass(t)},
	}}
	engine, written, registry := newEngine(t, source)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}

	reported := entries(t, written)
	if len(reported) != 1 {
		t.Fatalf("expected one refusal and got %d: %v", len(reported), reported)
	}
	if message := reported[0]["msg"]; message != "event_not_analysable" {
		t.Errorf("the report reads %q and should read %q", message, "event_not_analysable")
	}
	if reason := reported[0]["reason"]; reason != analysis.ReasonContractViolation {
		t.Errorf("the refusal reads %q and should read %q", reason, analysis.ReasonContractViolation)
	}
	if detail, _ := reported[0]["detail"].(string); !strings.Contains(detail, "event_class") {
		t.Errorf("the refusal does not name the field that broke: %q", detail)
	}
	if body := exposition(t, registry); strings.Contains(body, "seagull_analysis_unrouted_total") {
		t.Error("an event without a class was filed as a class this build does not know")
	}
}

// Normalization runs on the route the class sends the event down, and is
// counted apart from routing so the two questions stay separate: what the
// engine worked on, and how much of it arrived in a form it had to correct.
func TestTheEngineNormalizesWhatItRoutes(t *testing.T) {
	source := &oneBatch{records: []analysis.Record{
		{Partition: 1, Offset: 4, Value: inANonCanonicalForm(t)},
		{Partition: 1, Offset: 5, Value: admitted(t, "event-already-canonical")},
	}}
	engine, written, registry := newEngine(t, source)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}
	if reported := entries(t, written); len(reported) != 0 {
		t.Errorf("normalizing an event reported something: %v", reported)
	}

	body := exposition(t, registry)
	for _, expected := range []string{
		`seagull_analysis_routed_total{route="authentication"} 2`,
		`seagull_analysis_normalized_total{route="authentication"} 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("%s missing from the exposition:\n%s", expected, body)
		}
	}
}

// Detection is a stage on the route rather than a process of its own, so what
// proves it is the engine deciding a routed event against the ruleset it is
// pinned to and reporting what fired.
func TestARoutedEventIsDecidedAgainstTheRulesetTheProcessIsPinnedTo(t *testing.T) {
	rules := pinned{
		id:   "6a1cb0f4d2e8917c",
		held: true,
		programs: []*detection.Program{
			compiled(t, "authentication.failed", "failure"),
			compiled(t, "authentication.succeeded", "success"),
		},
	}
	source := &oneBatch{records: []analysis.Record{
		{Partition: 4, Offset: 11, Value: admitted(t, "event-one")},
		{Partition: 4, Offset: 12, Value: admitted(t, "event-two")},
	}}
	engine, written, registry := engineOn(t, source, rules, slog.LevelInfo)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}

	reported := entries(t, written)
	if len(reported) != 2 {
		t.Fatalf("two failed authentications produced %d detections: %v", len(reported), reported)
	}
	first := reported[0]
	for field, expected := range map[string]any{
		"msg":       "detection",
		"rule":      "authentication.failed",
		"revision":  3.0,
		"severity":  "high",
		"ruleset":   rules.id,
		"event":     "event-one",
		"agent":     "dev-agent-01",
		"tenant":    "default",
		"partition": 4.0,
		"offset":    11.0,
	} {
		if held := first[field]; held != expected {
			t.Errorf("the detection reports %s as %v and should report %v", field, held, expected)
		}
	}
	if fields, _ := first["fields"].([]any); len(fields) != 1 || fields[0] != "authentication.outcome" {
		t.Errorf("the detection names %v as what the rule read", first["fields"])
	}

	body := exposition(t, registry)
	for _, expected := range []string{
		`seagull_detection_evaluations_total{route="authentication"} 4`,
		`seagull_detection_matches_total{route="authentication",severity="high"} 2`,
		`seagull_detection_seconds_count{route="authentication"} 2`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("%s missing from the exposition:\n%s", expected, body)
		}
	}
}

// A detection says what decided it and never what the event held. Evidence is
// owed to an investigation and belongs in the detection record; a log line is
// not the place to copy attacker input into.
func TestADetectionDoesNotQuoteWhatTheEventHeld(t *testing.T) {
	rules := pinned{
		id:       "6a1cb0f4d2e8917c",
		held:     true,
		programs: []*detection.Program{compiled(t, "authentication.failed", "failure")},
	}
	source := &oneBatch{records: []analysis.Record{
		{Partition: 0, Offset: 1, Value: admitted(t, "event-one")},
	}}
	engine, written, _ := engineOn(t, source, rules, slog.LevelInfo)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}

	for _, held := range []string{"root", "203.0.113.10", "Failed password"} {
		if strings.Contains(written.String(), held) {
			t.Errorf("the detection quoted %q out of the event", held)
		}
	}
}

// A process whose registry has not pinned a ruleset still routes and still
// normalizes: detection is a stage, and a stage with nothing to run is not a
// reason to stop reading the backbone.
func TestAnEngineWithNoRulesetRoutesWithoutDeciding(t *testing.T) {
	source := &oneBatch{records: []analysis.Record{
		{Partition: 0, Offset: 1, Value: admitted(t, "event-one")},
	}}
	engine, written, registry := engineOn(t, source, pinned{}, slog.LevelInfo)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}
	if reported := entries(t, written); len(reported) != 0 {
		t.Errorf("an engine with no ruleset reported %v", reported)
	}

	body := exposition(t, registry)
	if !strings.Contains(body, `seagull_analysis_routed_total{route="authentication"} 1`) {
		t.Errorf("the event was not routed:\n%s", body)
	}
	if strings.Contains(body, "seagull_detection_seconds_count") {
		t.Error("an engine with no ruleset timed a decision it never made")
	}
}

// A rule may ask three questions about one field, and the report says which
// fields it read rather than how many times it read them.
func TestADetectionNamesEachFieldTheRuleReadOnce(t *testing.T) {
	program, err := detection.Compile(detection.Rule{
		ID:          "authentication.failed_from_outside",
		Revision:    1,
		Name:        "An authentication failed from outside the estate",
		Description: "A rule that asks about one field more than once.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.All{Terms: []detection.Expression{
			detection.Predicate{
				Field:    "authentication.outcome",
				Operator: detection.Equals,
				Values:   []detection.Value{detection.TextValue("failure")},
			},
			detection.Not{Term: detection.Any{Terms: []detection.Expression{
				detection.Predicate{
					Field:    "authentication.network.source.ip",
					Operator: detection.StartsWith,
					Values:   []detection.Value{detection.TextValue("10.")},
				},
				detection.Predicate{
					Field:    "authentication.network.source.ip",
					Operator: detection.StartsWith,
					Values:   []detection.Value{detection.TextValue("192.168.")},
				},
			}}},
		}},
		Severity: detection.Medium,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("compile the rule: %v", err)
	}

	source := &oneBatch{records: []analysis.Record{
		{Partition: 0, Offset: 1, Value: admitted(t, "event-one")},
	}}
	rules := pinned{id: "6a1cb0f4d2e8917c", held: true, programs: []*detection.Program{program}}
	engine, written, _ := engineOn(t, source, rules, slog.LevelInfo)

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}

	reported := entries(t, written)
	if len(reported) != 1 {
		t.Fatalf("one event produced %d detections", len(reported))
	}
	fields, _ := reported[0]["fields"].([]any)
	if len(fields) != 2 || fields[0] != "authentication.outcome" || fields[1] != "authentication.network.source.ip" {
		t.Errorf("the detection names %v as what the rule read", fields)
	}
}
