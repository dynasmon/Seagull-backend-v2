package alertstore_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/alertstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type sink struct {
	raised   [][]*alertv1.Alert
	known    map[string]struct{}
	refusals int
}

func (s *sink) Raise(_ context.Context, alerts []*alertv1.Alert) (int, error) {
	if s.refusals > 0 {
		s.refusals--
		return 0, errors.New("the store is not answering")
	}
	if s.known == nil {
		s.known = map[string]struct{}{}
	}
	added := 0
	for _, one := range alerts {
		if _, already := s.known[one.GetAlertId()]; !already {
			s.known[one.GetAlertId()] = struct{}{}
			added++
		}
	}
	s.raised = append(s.raised, alerts)
	return added, nil
}

type source struct {
	batches [][]alertstore.Record
}

func (s *source) Consume(ctx context.Context, deliver alertstore.Deliver) error {
	for _, batch := range s.batches {
		if err := deliver(ctx, batch); err != nil {
			return err
		}
	}
	return nil
}

func detection(id string, severity detectionv1.Severity) *detectionv1.Detection {
	return &detectionv1.Detection{
		DetectionId: id,
		Rule:        &detectionv1.Rule{Id: "ssh_password_failure", Revision: 1, Name: "SSH password failure"},
		Severity:    severity,
		EventClass:  eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Origin:      &eventv1.Origin{TenantId: "acme", AgentId: "dev-agent-01"},
		EventTime:   timestamppb.New(time.Date(2026, 8, 30, 11, 0, 0, 0, time.UTC)),
	}
}

func record(t *testing.T, made *detectionv1.Detection) alertstore.Record {
	t.Helper()
	encoded, err := proto.Marshal(made)
	if err != nil {
		t.Fatalf("marshal detection: %v", err)
	}
	return alertstore.Record{Key: []byte(made.GetOrigin().GetAgentId()), Value: encoded}
}

func writer(t *testing.T, from *source, into *sink) *alertstore.Writer {
	t.Helper()
	made, err := alertstore.NewWriter(alertstore.WriterOptions{
		Source:        from,
		Sink:          into,
		Floor:         detectionv1.Severity_SEVERITY_MEDIUM,
		Metrics:       alertstore.NewMetrics(metrics.New(t.Name())),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:           func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) },
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 2 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	return made
}

func TestOnlyWhatClearsTheFloorBecomesSomebodysWork(t *testing.T) {
	from := &source{batches: [][]alertstore.Record{{
		record(t, detection("low", detectionv1.Severity_SEVERITY_LOW)),
		record(t, detection("medium", detectionv1.Severity_SEVERITY_MEDIUM)),
		record(t, detection("high", detectionv1.Severity_SEVERITY_HIGH)),
		record(t, detection("critical", detectionv1.Severity_SEVERITY_CRITICAL)),
		record(t, detection("none", detectionv1.Severity_SEVERITY_UNSPECIFIED)),
	}}}
	into := &sink{}

	if err := writer(t, from, into).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(into.raised) != 1 {
		t.Fatalf("the writer made %d calls to the store", len(into.raised))
	}

	raised := map[string]bool{}
	for _, one := range into.raised[0] {
		raised[one.GetAlertId()] = true
	}
	for _, wanted := range []string{"medium", "high", "critical"} {
		if !raised[wanted] {
			t.Errorf("a %s detection raised no alert", wanted)
		}
	}
	for _, refused := range []string{"low", "none"} {
		if raised[refused] {
			t.Errorf("a %s detection raised an alert", refused)
		}
	}
}

func TestAReplayedBatchRaisesNothingNew(t *testing.T) {
	batch := []alertstore.Record{record(t, detection("bc84b318", detectionv1.Severity_SEVERITY_HIGH))}
	into := &sink{}

	if err := writer(t, &source{batches: [][]alertstore.Record{batch, batch}}, into).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(into.raised) != 2 {
		t.Fatalf("the store was written to %d times", len(into.raised))
	}
	if len(into.known) != 1 {
		t.Fatalf("replaying one detection left %d alerts", len(into.known))
	}
	if into.raised[0][0].GetAlertId() != into.raised[1][0].GetAlertId() {
		t.Error("the same detection was raised under two names")
	}
}

func TestARecordTheWriterCannotUseIsSteppedOverRatherThanHoldingTheBatch(t *testing.T) {
	untenanted := detection("untenanted", detectionv1.Severity_SEVERITY_HIGH)
	untenanted.Origin = &eventv1.Origin{AgentId: "dev-agent-01"}

	from := &source{batches: [][]alertstore.Record{{
		{Key: []byte("dev-agent-01"), Value: []byte("this is not a detection")},
		record(t, untenanted),
		record(t, detection("usable", detectionv1.Severity_SEVERITY_HIGH)),
	}}}
	into := &sink{}

	if err := writer(t, from, into).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(into.raised[0]) != 1 || into.raised[0][0].GetAlertId() != "usable" {
		t.Fatalf("the batch raised %d alerts", len(into.raised[0]))
	}
}

func TestAStoreThatWillNotTakeABatchHoldsTheConsumerRatherThanLosingIt(t *testing.T) {
	from := &source{batches: [][]alertstore.Record{{record(t, detection("held", detectionv1.Severity_SEVERITY_HIGH))}}}
	into := &sink{refusals: 3}

	if err := writer(t, from, into).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(into.known) != 1 {
		t.Fatalf("the retried batch left %d alerts", len(into.known))
	}
}

func TestAWriterWithoutAFloorRefusesToStart(t *testing.T) {
	_, err := alertstore.NewWriter(alertstore.WriterOptions{
		Source:        &source{},
		Sink:          &sink{},
		Metrics:       alertstore.NewMetrics(metrics.New(t.Name())),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: time.Second,
	})
	if err == nil {
		t.Fatal("a writer with no severity floor started")
	}
}
