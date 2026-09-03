package alertstore_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/alertstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

// The incident half of the store as far as the writer is concerned: a story is
// opened once and recognised every time after, which is how a replayed batch
// leaves one incident.
type stories struct {
	opened   map[string]*incidentv1.Incident
	batches  [][]*incidentv1.Incident
	refusals int
}

func (s *stories) Open(_ context.Context, told []*incidentv1.Incident) ([]incident.Outcome, error) {
	if s.refusals > 0 {
		s.refusals--
		return nil, errors.New("the store is not answering")
	}
	if s.opened == nil {
		s.opened = map[string]*incidentv1.Incident{}
	}

	outcomes := make([]incident.Outcome, len(told))
	for index, one := range told {
		if _, already := s.opened[one.GetIncidentId()]; already {
			outcomes[index] = incident.OutcomeRepeated
			continue
		}
		s.opened[one.GetIncidentId()] = one
		outcomes[index] = incident.OutcomeRaised
	}
	s.batches = append(s.batches, told)
	return outcomes, nil
}

func (s *stories) count() int { return len(s.opened) }

// The store as far as the writer is concerned: it folds on the key inside the
// window and refuses inside a cooldown, exactly as the relational one does, so
// what this proves is the writer's half — suppression, the floor, and retrying
// until a batch is durable.
type sink struct {
	batches  [][]alert.Candidate
	open     map[string]string
	lastSeen map[string]time.Time
	folded   map[string]string
	refusals int
}

func (s *sink) Record(_ context.Context, candidates []alert.Candidate) ([]alert.Outcome, error) {
	if s.refusals > 0 {
		s.refusals--
		return nil, errors.New("the store is not answering")
	}
	if s.open == nil {
		s.open, s.lastSeen, s.folded = map[string]string{}, map[string]time.Time{}, map[string]string{}
	}

	outcomes := make([]alert.Outcome, len(candidates))
	for index, candidate := range candidates {
		switch into, already := s.folded[candidate.DetectionID]; {
		case already:
			outcomes[index] = alert.OutcomeRepeated
			_ = into
		case s.open[candidate.Key] != "" && !candidate.At.After(s.lastSeen[candidate.Key].Add(candidate.Window)):
			s.folded[candidate.DetectionID] = s.open[candidate.Key]
			if candidate.At.After(s.lastSeen[candidate.Key]) {
				s.lastSeen[candidate.Key] = candidate.At
			}
			outcomes[index] = alert.OutcomeFolded
		default:
			s.open[candidate.Key] = candidate.Alert.GetAlertId()
			s.lastSeen[candidate.Key] = candidate.At
			s.folded[candidate.DetectionID] = candidate.Alert.GetAlertId()
			outcomes[index] = alert.OutcomeRaised
		}
	}
	s.batches = append(s.batches, candidates)
	return outcomes, nil
}

func (s *sink) alerts() int { return len(s.open) }

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

func tuning(t *testing.T, suppressions ...alert.Suppression) *alert.Tuning {
	t.Helper()
	compiled, err := alert.NewTuning(
		alert.Fold{Keyed: []alert.Part{alert.PartRule, alert.PartAgent}, Window: 15 * time.Minute},
		nil, suppressions)
	if err != nil {
		t.Fatalf("compile a tuning: %v", err)
	}
	return compiled
}

func writer(t *testing.T, from *source, into *sink, suppressions ...alert.Suppression) *alertstore.Writer {
	t.Helper()
	return writerTelling(t, from, into, &stories{}, suppressions...)
}

func writerTelling(t *testing.T, from *source, into *sink, told *stories, suppressions ...alert.Suppression) *alertstore.Writer {
	t.Helper()
	made, err := alertstore.NewWriter(alertstore.WriterOptions{
		Source:        from,
		Sink:          into,
		Stories:       told,
		Tuning:        tuning(t, suppressions...),
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
	if len(into.batches) != 1 {
		t.Fatalf("the writer made %d calls to the store", len(into.batches))
	}

	raised := map[string]bool{}
	for _, one := range into.batches[0] {
		raised[one.Alert.GetAlertId()] = true
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
	if len(into.batches) != 2 {
		t.Fatalf("the store was written to %d times", len(into.batches))
	}
	if into.alerts() != 1 {
		t.Fatalf("replaying one detection left %d alerts", into.alerts())
	}
	if into.batches[0][0].Alert.GetAlertId() != into.batches[1][0].Alert.GetAlertId() {
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
	if len(into.batches[0]) != 1 || into.batches[0][0].Alert.GetAlertId() != "usable" {
		t.Fatalf("the batch raised %d alerts", len(into.batches[0]))
	}
}

func TestAStoreThatWillNotTakeABatchHoldsTheConsumerRatherThanLosingIt(t *testing.T) {
	from := &source{batches: [][]alertstore.Record{{record(t, detection("held", detectionv1.Severity_SEVERITY_HIGH))}}}
	into := &sink{refusals: 3}

	if err := writer(t, from, into).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if into.alerts() != 1 {
		t.Fatalf("the retried batch left %d alerts", into.alerts())
	}
}

func TestAWriterWithoutAFloorRefusesToStart(t *testing.T) {
	_, err := alertstore.NewWriter(alertstore.WriterOptions{
		Source:        &source{},
		Sink:          &sink{},
		Stories:       &stories{},
		Tuning:        tuning(t),
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

func TestASuppressedDetectionNeverReachesTheStore(t *testing.T) {
	from := &source{batches: [][]alertstore.Record{{
		record(t, detection("from-the-scanner", detectionv1.Severity_SEVERITY_HIGH)),
	}}}
	into := &sink{}

	made := writer(t, from, into, alert.Suppression{
		When:   alert.Selector{alert.PartAgent: {"dev-agent-01"}},
		Reason: "our own credentialed scanner",
	})
	if err := made.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(into.batches) != 0 {
		t.Fatalf("a suppressed detection reached the store as %d batches", len(into.batches))
	}
	if into.alerts() != 0 {
		t.Fatalf("a suppressed detection left %d alerts", into.alerts())
	}
}

func TestDetectionsSharingAKeyBecomeOnePieceOfWork(t *testing.T) {
	var records []alertstore.Record
	for _, id := range []string{"first", "second", "third"} {
		records = append(records, record(t, detection(id, detectionv1.Severity_SEVERITY_HIGH)))
	}
	into := &sink{}

	if err := writer(t, &source{batches: [][]alertstore.Record{records}}, into).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if into.alerts() != 1 {
		t.Fatalf("three detections about one agent and one rule left %d alerts", into.alerts())
	}

	keys := map[string]struct{}{}
	for _, candidate := range into.batches[0] {
		keys[candidate.Key] = struct{}{}
	}
	if len(keys) != 1 {
		t.Fatalf("they carried %d correlation keys", len(keys))
	}
}

func story(id string, severity detectionv1.Severity) *detectionv1.Detection {
	told := detection(id, severity)
	told.Rule = &detectionv1.Rule{Id: "ssh.password_guessing_that_succeeded", Revision: 1}
	told.Correlation = &detectionv1.Correlation{
		Stages: []*detectionv1.Stage{
			{
				Name: "a failed password", EventId: "event-1",
				EventTime: timestamppb.New(time.Date(2026, 8, 30, 11, 0, 0, 0, time.UTC)),
			},
			{
				Name: "one that was accepted", EventId: "event-2",
				EventTime: timestamppb.New(time.Date(2026, 8, 30, 11, 0, 40, 0, time.UTC)),
			},
		},
		Window:      durationpb.New(5 * time.Minute),
		ClockSpread: durationpb.New(0),
	}
	return told
}

func TestAStoryBecomesAnIncidentAndNeverAnAlert(t *testing.T) {
	from := &source{batches: [][]alertstore.Record{{
		record(t, detection("a-single-finding", detectionv1.Severity_SEVERITY_HIGH)),
		record(t, story("a-story", detectionv1.Severity_SEVERITY_CRITICAL)),
	}}}
	into, told := &sink{}, &stories{}

	if err := writerTelling(t, from, into, told).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	if into.alerts() != 1 {
		t.Fatalf("the batch raised %d alerts", into.alerts())
	}
	if into.batches[0][0].Alert.GetAlertId() != "a-single-finding" {
		t.Errorf("the alert raised was %q", into.batches[0][0].Alert.GetAlertId())
	}
	if told.count() != 1 {
		t.Fatalf("the batch opened %d incidents", told.count())
	}
	one, opened := told.opened["a-story"]
	if !opened {
		t.Fatal("the story opened no incident under the detection that told it")
	}
	if len(one.GetStages()) != 2 || one.GetStages()[1].GetEventId() != "event-2" {
		t.Error("the incident does not name the events the story is made of")
	}
	if one.GetConfidence() != incidentv1.Confidence_CONFIDENCE_HIGH {
		t.Errorf("clocks that agreed left the story at %s", incident.Level(one.GetConfidence()))
	}
}

func TestAReplayedStoryOpensNothingNew(t *testing.T) {
	batch := []alertstore.Record{record(t, story("bc84b318", detectionv1.Severity_SEVERITY_CRITICAL))}
	into, told := &sink{}, &stories{}

	if err := writerTelling(t, &source{batches: [][]alertstore.Record{batch, batch}}, into, told).
		Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(told.batches) != 2 {
		t.Fatalf("the store was written to %d times", len(told.batches))
	}
	if told.count() != 1 {
		t.Fatalf("replaying one story left %d incidents", told.count())
	}
	if into.alerts() != 0 {
		t.Fatalf("a replayed story raised %d alerts", into.alerts())
	}
}

func TestAStoreThatWillNotTakeAStoryHoldsTheConsumerRatherThanLosingIt(t *testing.T) {
	from := &source{batches: [][]alertstore.Record{{record(t, story("held", detectionv1.Severity_SEVERITY_CRITICAL))}}}
	into, told := &sink{}, &stories{refusals: 3}

	if err := writerTelling(t, from, into, told).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if told.count() != 1 {
		t.Fatalf("the retried batch left %d incidents", told.count())
	}
}

func TestAWriterWithNowhereToOpenAStoryRefusesToStart(t *testing.T) {
	_, err := alertstore.NewWriter(alertstore.WriterOptions{
		Source:        &source{},
		Sink:          &sink{},
		Tuning:        tuning(t),
		Floor:         detectionv1.Severity_SEVERITY_MEDIUM,
		Metrics:       alertstore.NewMetrics(metrics.New(t.Name())),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: time.Second,
	})
	if err == nil {
		t.Fatal("a writer with nowhere to open an incident started")
	}
}

func TestAStoryTheEstateSuppressedNeverBecomesWorkEither(t *testing.T) {
	from := &source{batches: [][]alertstore.Record{{
		record(t, story("from-the-scanner", detectionv1.Severity_SEVERITY_CRITICAL)),
	}}}
	into, told := &sink{}, &stories{}

	made := writerTelling(t, from, into, told, alert.Suppression{
		When:   alert.Selector{alert.PartAgent: {"dev-agent-01"}},
		Reason: "our own credentialed scanner",
	})
	if err := made.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if told.count() != 0 || len(told.batches) != 0 {
		t.Fatalf("a suppressed story left %d incidents", told.count())
	}
}
