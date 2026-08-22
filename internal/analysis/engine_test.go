package analysis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
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

func newEngine(t *testing.T, source analysis.Source) (*analysis.Engine, *bytes.Buffer, *metrics.Registry) {
	t.Helper()

	var written bytes.Buffer
	registry := metrics.New("test")
	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:  source,
		Metrics: analysis.NewMetrics(registry),
		Logger:  slog.New(slog.NewJSONHandler(&written, &slog.HandlerOptions{Level: slog.LevelWarn})),
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
		"no source":  {Metrics: analysis.NewMetrics(registry), Logger: logger},
		"no metrics": {Source: &oneBatch{}, Logger: logger},
		"no logger":  {Source: &oneBatch{}, Metrics: analysis.NewMetrics(metrics.New("other"))},
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
