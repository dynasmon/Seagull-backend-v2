package analysis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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

func newEngine(t *testing.T, source analysis.Source) (*analysis.Engine, *bytes.Buffer) {
	t.Helper()

	var written bytes.Buffer
	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:  source,
		Metrics: analysis.NewMetrics(metrics.New("test")),
		Logger:  slog.New(slog.NewJSONHandler(&written, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return engine, &written
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
	engine, written := newEngine(t, source)

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
	engine, written := newEngine(t, source)

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
	engine, written := newEngine(t, source)

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
	engine, _ := newEngine(t, source)

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
