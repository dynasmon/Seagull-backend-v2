//go:build integration

package integration_test

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

	"github.com/dynasmon/Seagull-backend-v2/internal/alertstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

func correlatedIn(tenant, id string, at time.Time, spread time.Duration) *detectionv1.Detection {
	return &detectionv1.Detection{
		DetectionId: id,
		Rule: &detectionv1.Rule{
			Id:       "ssh.password_guessing_that_succeeded",
			Revision: 1,
			Name:     "SSH password guessing that succeeded",
			Source:   &detectionv1.Source{Catalogue: "sigma", Identifier: "5013fd8a"},
		},
		RulesetId:  "89ab5f2c1d",
		Severity:   detectionv1.Severity_SEVERITY_CRITICAL,
		Technique:  &detectionv1.Technique{Tactic: "credential_access", Id: "T1110.001", Name: "Password Guessing"},
		EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Origin:     &eventv1.Origin{TenantId: tenant, AgentId: "dev-agent-01"},
		EventTime:  timestamppb.New(at.Add(40 * time.Second)),
		Correlation: &detectionv1.Correlation{
			Stages: []*detectionv1.Stage{
				{Name: "a failed password", EventId: id + "-event-1", EventTime: timestamppb.New(at)},
				{Name: "one that was accepted", EventId: id + "-event-2", EventTime: timestamppb.New(at.Add(40 * time.Second))},
			},
			Window:      durationpb.New(5 * time.Minute),
			ClockSpread: durationpb.New(spread),
			Group: []*detectionv1.Grouping{
				{Field: "authentication.network.source.ip", Value: "203.0.113.10"},
				{Field: "origin.agent_id", Value: "dev-agent-01"},
			},
		},
	}
}

func openedFrom(t *testing.T, tenant, id string, at time.Time, spread time.Duration) *incidentv1.Incident {
	t.Helper()
	told, err := incident.Raise(correlatedIn(tenant, id, at, spread), at.Add(time.Minute))
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	return told
}

func opened(t *testing.T, stories *postgres.Incidents, told ...*incidentv1.Incident) []incident.Outcome {
	t.Helper()
	outcomes, err := stories.Open(context.Background(), told)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return outcomes
}

func TestWhatWasStoredComesBackAsTheStoryThatWasOpened(t *testing.T) {
	stories := migratedAlertStore(t, alertStoreAddress(t)).Incidents()
	tenant := isolated(t)
	at := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)

	told := openedFrom(t, tenant, tenant+"-round-trip", at, 0)
	if outcomes := opened(t, stories, told); outcomes[0] != incident.OutcomeRaised {
		t.Fatalf("opening a story came to %s", outcomes[0])
	}

	read, err := stories.Incident(context.Background(), told.GetIncidentId(), []string{tenant})
	if err != nil {
		t.Fatalf("read the incident back: %v", err)
	}

	if read.GetDetectionId() != told.GetDetectionId() || read.GetRulesetId() != told.GetRulesetId() {
		t.Error("the story does not name what told it")
	}
	if read.GetSeverity() != told.GetSeverity() || read.GetConfidence() != incidentv1.Confidence_CONFIDENCE_HIGH {
		t.Errorf("severity %s, confidence %s", read.GetSeverity(), incident.Level(read.GetConfidence()))
	}
	if len(read.GetStages()) != 2 {
		t.Fatalf("the stored story carries %d stages", len(read.GetStages()))
	}
	for index, stage := range read.GetStages() {
		was := told.GetStages()[index]
		if stage.GetName() != was.GetName() || stage.GetEventId() != was.GetEventId() {
			t.Errorf("stage %d came back as %q on %q", index, stage.GetName(), stage.GetEventId())
		}
		if !stage.GetEventTime().AsTime().Equal(was.GetEventTime().AsTime()) {
			t.Errorf("stage %d came back at %s", index, stage.GetEventTime().AsTime())
		}
	}
	if len(read.GetGroup()) != 2 || read.GetGroup()[0].GetValue() != "203.0.113.10" {
		t.Error("the stored story does not say what it is about")
	}
	if read.GetWindow().AsDuration() != 5*time.Minute {
		t.Errorf("the window came back as %s", read.GetWindow().AsDuration())
	}
	if !read.GetFirstEventTime().AsTime().Equal(at) || !read.GetLastEventTime().AsTime().Equal(at.Add(40*time.Second)) {
		t.Error("the span the story covers did not survive the store")
	}
}

func TestAClockSpreadTheStoreKeepsIsTheOneConfidenceWasDecidedFrom(t *testing.T) {
	stories := migratedAlertStore(t, alertStoreAddress(t)).Incidents()
	tenant := isolated(t)
	at := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)

	for _, one := range []struct {
		id     string
		spread time.Duration
		want   incidentv1.Confidence
	}{
		{"ordered", 0, incidentv1.Confidence_CONFIDENCE_HIGH},
		{"inside-the-window", 2 * time.Minute, incidentv1.Confidence_CONFIDENCE_MEDIUM},
		{"beyond-the-window", 10 * time.Minute, incidentv1.Confidence_CONFIDENCE_LOW},
	} {
		told := openedFrom(t, tenant, tenant+"-"+one.id, at, one.spread)
		opened(t, stories, told)

		read, err := stories.Incident(context.Background(), told.GetIncidentId(), []string{tenant})
		if err != nil {
			t.Fatalf("read %s back: %v", one.id, err)
		}
		if read.GetConfidence() != one.want {
			t.Errorf("a spread of %s came back as %s", one.spread, incident.Level(read.GetConfidence()))
		}
		if read.GetClockSpread().AsDuration() != one.spread {
			t.Errorf("the spread came back as %s", read.GetClockSpread().AsDuration())
		}
	}
}

func TestAReplayedCorrelationOpensNoSecondIncidentNorUndoesTriage(t *testing.T) {
	stories := migratedAlertStore(t, alertStoreAddress(t)).Incidents()
	tenant := isolated(t)
	at := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)
	told := openedFrom(t, tenant, tenant+"-replayed", at, 0)

	opened(t, stories, told)
	moved, err := stories.Move(context.Background(), told.GetIncidentId(), []string{tenant},
		incident.Move{To: incident.InInvestigation, Actor: "dev-responder", At: at.Add(time.Hour)})
	if err != nil {
		t.Fatalf("move: %v", err)
	}

	if outcomes := opened(t, stories, openedFrom(t, tenant, tenant+"-replayed", at, 0)); outcomes[0] != incident.OutcomeRepeated {
		t.Fatalf("replaying a story came to %s", outcomes[0])
	}

	read, err := stories.Incident(context.Background(), told.GetIncidentId(), []string{tenant})
	if err != nil {
		t.Fatalf("read the incident back: %v", err)
	}
	if read.GetState() != moved.GetState() || read.GetRevision() != moved.GetRevision() {
		t.Fatalf("a replayed correlation put the story back to %s at revision %d",
			read.GetState(), read.GetRevision())
	}

	trail, err := stories.History(context.Background(), told.GetIncidentId(), []string{tenant})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if len(trail.GetTransitions()) != 2 {
		t.Fatalf("a replay left %d lines of trail", len(trail.GetTransitions()))
	}
}

func TestWorkingAStoryLeavesEveryStageWhereTheEngineWroteIt(t *testing.T) {
	stories := migratedAlertStore(t, alertStoreAddress(t)).Incidents()
	tenant := isolated(t)
	at := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)
	told := openedFrom(t, tenant, tenant+"-worked", at, 0)
	opened(t, stories, told)

	for _, step := range []incident.Move{
		{To: incident.Acknowledged, Actor: "dev-responder", At: at.Add(time.Hour)},
		{To: incident.FalsePositive, Note: "one operator retrying", Actor: "dev-responder", At: at.Add(2 * time.Hour)},
	} {
		if _, err := stories.Move(context.Background(), told.GetIncidentId(), []string{tenant}, step); err != nil {
			t.Fatalf("move to %s: %v", step.To, err)
		}
	}

	read, err := stories.Incident(context.Background(), told.GetIncidentId(), []string{tenant})
	if err != nil {
		t.Fatalf("read the incident back: %v", err)
	}
	if read.GetClosure().GetReason() != "one operator retrying" {
		t.Error("the closure does not carry what a correlation rule would be corrected from")
	}
	if len(read.GetStages()) != len(told.GetStages()) {
		t.Fatalf("working the story left %d stages", len(read.GetStages()))
	}
	for index, stage := range read.GetStages() {
		if stage.GetEventId() != told.GetStages()[index].GetEventId() {
			t.Errorf("stage %d names %q", index, stage.GetEventId())
		}
	}
	if read.GetDetectionId() != told.GetDetectionId() || read.GetConfidence() != told.GetConfidence() {
		t.Error("working the story changed what the platform measured about it")
	}
}

func TestTwoPeopleMovingOneStoryAtOnceLeavesOneWinnerAndOneRefusal(t *testing.T) {
	stories := migratedAlertStore(t, alertStoreAddress(t)).Incidents()
	tenant := isolated(t)
	at := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)
	told := openedFrom(t, tenant, tenant+"-contended", at, 0)
	opened(t, stories, told)

	first := incident.Move{To: incident.Acknowledged, Actor: "dev-responder", At: at.Add(time.Hour), Expected: 1}
	second := incident.Move{To: incident.InInvestigation, Actor: "dev-admin", At: at.Add(time.Hour), Expected: 1}

	if _, err := stories.Move(context.Background(), told.GetIncidentId(), []string{tenant}, first); err != nil {
		t.Fatalf("the first move was refused: %v", err)
	}
	_, err := stories.Move(context.Background(), told.GetIncidentId(), []string{tenant}, second)
	if !errors.Is(err, incident.ErrMoved) {
		t.Fatalf("the second move was answered %v", err)
	}

	trail, err := stories.History(context.Background(), told.GetIncidentId(), []string{tenant})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if len(trail.GetTransitions()) != 2 {
		t.Fatalf("one winner and one refusal left %d lines of trail", len(trail.GetTransitions()))
	}
}

func TestAStoryIsNeverReadOutsideItsTenant(t *testing.T) {
	stories := migratedAlertStore(t, alertStoreAddress(t)).Incidents()
	mine, theirs := isolated(t), isolated(t)
	at := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)
	told := openedFrom(t, mine, mine+"-scoped", at, 0)
	opened(t, stories, told)

	if _, err := stories.Incident(context.Background(), told.GetIncidentId(), []string{theirs}); !errors.Is(err, incident.ErrUnknownIncident) {
		t.Fatalf("another tenant read the story: %v", err)
	}
	if _, err := stories.History(context.Background(), told.GetIncidentId(), []string{theirs}); !errors.Is(err, incident.ErrUnknownIncident) {
		t.Fatalf("another tenant read the trail: %v", err)
	}
	move := incident.Move{To: incident.Acknowledged, Actor: "somebody-else", At: at.Add(time.Hour)}
	if _, err := stories.Move(context.Background(), told.GetIncidentId(), []string{theirs}, move); !errors.Is(err, incident.ErrUnknownIncident) {
		t.Fatalf("another tenant moved the story: %v", err)
	}

	page, err := stories.Page(context.Background(), &incidentv1.Query{}, []string{theirs})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.GetIncidents()) != 0 {
		t.Fatalf("another tenant listed %d stories", len(page.GetIncidents()))
	}
}

func TestAPageOfStoriesIsNewestFirstAndTheCursorWalksTheRestOfIt(t *testing.T) {
	stories := migratedAlertStore(t, alertStoreAddress(t)).Incidents()
	tenant := isolated(t)
	at := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)

	told := make([]*incidentv1.Incident, 0, 5)
	for index := range 5 {
		told = append(told, openedFrom(t, tenant, tenant+"-page-"+string(rune('a'+index)), at.Add(time.Duration(index)*time.Hour), 0))
	}
	opened(t, stories, told...)

	page, err := stories.Page(context.Background(), &incidentv1.Query{Limit: 2}, []string{tenant})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.GetIncidents()) != 2 || page.GetNextCursor() == "" {
		t.Fatalf("the first page holds %d stories and a cursor %q", len(page.GetIncidents()), page.GetNextCursor())
	}

	seen := map[string]bool{}
	for cursor := ""; ; {
		asked := &incidentv1.Query{Limit: 2, Cursor: cursor}
		page, err := stories.Page(context.Background(), asked, []string{tenant})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		var previous time.Time
		for _, one := range page.GetIncidents() {
			if seen[one.GetIncidentId()] {
				t.Fatalf("%s was listed twice", one.GetIncidentId())
			}
			seen[one.GetIncidentId()] = true
			if !previous.IsZero() && one.GetRaisedAt().AsTime().After(previous) {
				t.Fatal("the page is not newest first")
			}
			previous = one.GetRaisedAt().AsTime()
		}
		if page.GetNextCursor() == "" {
			break
		}
		cursor = page.GetNextCursor()
	}
	if len(seen) != 5 {
		t.Fatalf("the cursor walked %d of five stories", len(seen))
	}

	if _, err := stories.Page(context.Background(), &incidentv1.Query{Cursor: "not a cursor"}, []string{tenant}); !errors.Is(err, incident.ErrCursor) {
		t.Fatalf("a cursor nobody issued was answered %v", err)
	}
}

func TestAListingOfStoriesAnswersTheQuestionAnOperatorActuallyAsks(t *testing.T) {
	stories := migratedAlertStore(t, alertStoreAddress(t)).Incidents()
	tenant := isolated(t)
	at := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)

	trusted := openedFrom(t, tenant, tenant+"-trusted", at, 0)
	doubted := openedFrom(t, tenant, tenant+"-doubted", at.Add(time.Hour), 10*time.Minute)
	opened(t, stories, trusted, doubted)

	if _, err := stories.Move(context.Background(), doubted.GetIncidentId(), []string{tenant},
		incident.Move{To: incident.Acknowledged, Actor: "dev-responder", At: at.Add(2 * time.Hour)}); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}

	for _, one := range []struct {
		what   string
		asked  *incidentv1.Query
		wanted string
	}{
		{"still open", &incidentv1.Query{States: []incidentv1.State{incidentv1.State_STATE_OPEN}}, trusted.GetIncidentId()},
		{"worth believing", &incidentv1.Query{Confidences: []incidentv1.Confidence{incidentv1.Confidence_CONFIDENCE_HIGH}}, trusted.GetIncidentId()},
		{"not ordered", &incidentv1.Query{Confidences: []incidentv1.Confidence{incidentv1.Confidence_CONFIDENCE_LOW}}, doubted.GetIncidentId()},
	} {
		page, err := stories.Page(context.Background(), one.asked, []string{tenant})
		if err != nil {
			t.Fatalf("list %s: %v", one.what, err)
		}
		if len(page.GetIncidents()) != 1 || page.GetIncidents()[0].GetIncidentId() != one.wanted {
			t.Errorf("%s answered %d stories", one.what, len(page.GetIncidents()))
		}
	}
}

func TestTheWriterTurnsARealCorrelationIntoAStoryAndNeverIntoAnAlert(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	tenant := isolated(t)
	at := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)

	records := make([]alertstore.Record, 0, 2)
	for _, made := range []*detectionv1.Detection{
		detectedIn(tenant, tenant+"-finding", detectionv1.Severity_SEVERITY_HIGH, at),
		correlatedIn(tenant, tenant+"-story", at, 0),
	} {
		encoded, err := proto.Marshal(made)
		if err != nil {
			t.Fatalf("marshal a detection: %v", err)
		}
		records = append(records, alertstore.Record{Key: []byte("dev-agent-01"), Value: encoded})
	}

	build := func() *alertstore.Writer {
		writer, err := alertstore.NewWriter(alertstore.WriterOptions{
			Source:        oneBatch{records: records},
			Sink:          store,
			Stories:       store.Incidents(),
			Tuning:        folding(t, 15*time.Minute, 0),
			Floor:         detectionv1.Severity_SEVERITY_MEDIUM,
			Metrics:       alertstore.NewMetrics(metrics.New("integration-incidents")),
			Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			WriteTimeout:  30 * time.Second,
			RetryDelay:    100 * time.Millisecond,
			MaxRetryDelay: time.Second,
		})
		if err != nil {
			t.Fatalf("build the writer: %v", err)
		}
		return writer
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := build().Run(ctx); err != nil {
		t.Fatalf("run the writer: %v", err)
	}
	if err := build().Run(ctx); err != nil {
		t.Fatalf("replay the batch: %v", err)
	}

	stories, err := store.Incidents().Page(ctx, &incidentv1.Query{}, []string{tenant})
	if err != nil {
		t.Fatalf("list the stories: %v", err)
	}
	if len(stories.GetIncidents()) != 1 {
		t.Fatalf("one correlation, replayed, left %d incidents", len(stories.GetIncidents()))
	}
	told := stories.GetIncidents()[0]
	if told.GetIncidentId() != tenant+"-story" {
		t.Errorf("the incident is named %q", told.GetIncidentId())
	}
	if len(told.GetStages()) != 2 || told.GetStages()[0].GetEventId() != tenant+"-story-event-1" {
		t.Error("the incident does not trace back to the events the story is made of")
	}

	raised, err := store.Page(ctx, &alertv1.Query{}, []string{tenant})
	if err != nil {
		t.Fatalf("list the alerts: %v", err)
	}
	if len(raised.GetAlerts()) != 1 {
		t.Fatalf("the batch raised %d alerts", len(raised.GetAlerts()))
	}
	if raised.GetAlerts()[0].GetAlertId() != tenant+"-finding" {
		t.Errorf("the alert raised was %q: a story became somebody's alert", raised.GetAlerts()[0].GetAlertId())
	}
}
