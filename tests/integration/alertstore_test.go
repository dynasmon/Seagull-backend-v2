//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/alertstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func alertStoreAddress(t *testing.T) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("SEAGULL_TEST_ALERT_STORE"))
	if value == "" {
		t.Skip("set SEAGULL_TEST_ALERT_STORE to run the alert store integration suite")
	}
	return value
}

func alertSettings(address string) postgres.Config {
	return postgres.Config{
		Address:     address,
		Database:    storeDatabase,
		User:        storeUser,
		Password:    "seagull",
		SSLMode:     "disable",
		MaxConns:    8,
		Timeout:     30 * time.Second,
		ConnTimeout: 10 * time.Second,
	}
}

// The schema arrives by command, as in a deployment; the store only verifies.
func migratedAlertStore(t *testing.T, address string) *postgres.Store {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	migrator, err := postgres.NewMigrator(ctx, alertSettings(address))
	if err != nil {
		t.Fatalf("build the migrator: %v", err)
	}
	if _, err := migrator.Apply(ctx); err != nil {
		t.Fatalf("apply the schema: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatalf("close the migrator: %v", err)
	}

	store, err := postgres.New(ctx, alertSettings(address))
	if err != nil {
		t.Fatalf("build the alert store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass verification: %v", err)
	}
	return store
}

// A tenant nobody else uses, drawn per run: raising is idempotent on the alert's
// name, so a suite that reuses one would find what the run before it left and
// prove nothing.
func isolated(t *testing.T) string {
	t.Helper()
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("draw a tenant: %v", err)
	}
	return "tenant-" + hex.EncodeToString(seed[:])
}

func raisedFrom(t *testing.T, tenant, id string, severity detectionv1.Severity, at time.Time) *alertv1.Alert {
	t.Helper()
	made, err := alert.Raise(&detectionv1.Detection{
		DetectionId: id,
		Rule: &detectionv1.Rule{
			Id:       "ssh.failed_password_from_outside",
			Revision: 3,
			Name:     "Failed SSH password from outside the estate",
			Source:   &detectionv1.Source{Catalogue: "sigma", Identifier: "5013fd8a"},
		},
		Severity:   severity,
		Technique:  &detectionv1.Technique{Tactic: "credential_access", Id: "T1110.001", Name: "Password Guessing"},
		EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Origin:     &eventv1.Origin{TenantId: tenant, AgentId: "integration-agent"},
		EventTime:  timestamppb.New(at.Add(-time.Minute)),
	}, at)
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	return made
}

func TestAReplayedDetectionDoesNotRaiseASecondAlertNorUndoTriage(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx := context.Background()

	tenant := isolated(t)
	one := raisedFrom(t, tenant, tenant+"-alert", detectionv1.Severity_SEVERITY_HIGH, time.Now().UTC())

	added, err := store.Raise(ctx, []*alertv1.Alert{one})
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	if added != 1 {
		t.Fatalf("the first raise added %d alerts", added)
	}

	moved, err := store.Move(ctx, one.GetAlertId(), []string{tenant}, alert.Move{
		To: alert.Acknowledged, Actor: "integration-responder", At: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if moved.GetRevision() != 2 {
		t.Fatalf("the acknowledged alert is at revision %d", moved.GetRevision())
	}

	added, err = store.Raise(ctx, []*alertv1.Alert{one})
	if err != nil {
		t.Fatalf("raise again: %v", err)
	}
	if added != 0 {
		t.Fatalf("replaying the detection raised %d alerts", added)
	}

	read, err := store.Alert(ctx, one.GetAlertId(), []string{tenant})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if read.GetState() != alertv1.State_STATE_ACKNOWLEDGED || read.GetRevision() != 2 {
		t.Fatalf("the replay put the alert back to %s at revision %d", read.GetState(), read.GetRevision())
	}
	if read.GetChangedBy() != "integration-responder" {
		t.Errorf("the replay reattributed the alert to %q", read.GetChangedBy())
	}
}

func TestWhatWasStoredComesBackAsTheAlertThatWasRaised(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx := context.Background()

	tenant := isolated(t)
	raised := raisedFrom(t, tenant, tenant+"-alert", detectionv1.Severity_SEVERITY_CRITICAL, time.Now().UTC().Truncate(time.Millisecond))

	if _, err := store.Raise(ctx, []*alertv1.Alert{raised}); err != nil {
		t.Fatalf("raise: %v", err)
	}

	read, err := store.Alert(ctx, raised.GetAlertId(), []string{tenant})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	for field, pair := range map[string][2]string{
		"tenant":     {read.GetTenantId(), raised.GetTenantId()},
		"detection":  {read.GetDetectionId(), raised.GetDetectionId()},
		"rule":       {read.GetRule().GetId(), raised.GetRule().GetId()},
		"rule name":  {read.GetRule().GetName(), raised.GetRule().GetName()},
		"catalogue":  {read.GetRule().GetSource().GetCatalogue(), raised.GetRule().GetSource().GetCatalogue()},
		"technique":  {read.GetTechnique().GetId(), raised.GetTechnique().GetId()},
		"agent":      {read.GetAgentId(), raised.GetAgentId()},
		"changed by": {read.GetChangedBy(), raised.GetChangedBy()},
	} {
		if pair[0] != pair[1] {
			t.Errorf("the %s came back %q and was stored as %q", field, pair[0], pair[1])
		}
	}
	if read.GetSeverity() != raised.GetSeverity() || read.GetEventClass() != raised.GetEventClass() {
		t.Errorf("severity or class came back as %s / %s", read.GetSeverity(), read.GetEventClass())
	}
	if !read.GetRaisedAt().AsTime().Equal(raised.GetRaisedAt().AsTime()) {
		t.Errorf("it was raised at %s and came back at %s", raised.GetRaisedAt().AsTime(), read.GetRaisedAt().AsTime())
	}
	if !read.GetEventTime().AsTime().Equal(raised.GetEventTime().AsTime()) {
		t.Errorf("the event happened at %s and came back at %s", raised.GetEventTime().AsTime(), read.GetEventTime().AsTime())
	}

	trail, err := store.History(ctx, raised.GetAlertId(), []string{tenant})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if len(trail.GetTransitions()) != 1 {
		t.Fatalf("a freshly raised alert has %d lines of trail", len(trail.GetTransitions()))
	}
	if trail.GetTransitions()[0].GetActor() != alert.Platform {
		t.Errorf("the alert was raised by %q", trail.GetTransitions()[0].GetActor())
	}
}

func TestTwoPeopleMovingOneAlertAtOnceLeavesOneWinnerAndOneRefusal(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx := context.Background()

	tenant := isolated(t)
	raised := raisedFrom(t, tenant, tenant+"-alert", detectionv1.Severity_SEVERITY_HIGH, time.Now().UTC())
	if _, err := store.Raise(ctx, []*alertv1.Alert{raised}); err != nil {
		t.Fatalf("raise: %v", err)
	}

	var (
		wait     sync.WaitGroup
		mutex    sync.Mutex
		outcomes []error
	)
	for _, actor := range []string{"alice", "bob"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.Move(ctx, raised.GetAlertId(), []string{tenant}, alert.Move{
				To: alert.Acknowledged, Actor: actor, At: time.Now().UTC(), Expected: 1,
			})
			mutex.Lock()
			outcomes = append(outcomes, err)
			mutex.Unlock()
		}()
	}
	wait.Wait()

	won, refused := 0, 0
	for _, err := range outcomes {
		switch {
		case err == nil:
			won++
		case errors.Is(err, alert.ErrMoved):
			refused++
		default:
			t.Fatalf("a concurrent move failed for a third reason: %v", err)
		}
	}
	if won != 1 || refused != 1 {
		t.Fatalf("%d moves won and %d were refused", won, refused)
	}

	trail, err := store.History(ctx, raised.GetAlertId(), []string{tenant})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if len(trail.GetTransitions()) != 2 {
		t.Fatalf("the trail carries %d lines after one winning move", len(trail.GetTransitions()))
	}
}

func TestARefusedMoveLeavesNeitherAStateNorALineOfTrail(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx := context.Background()

	tenant := isolated(t)
	raised := raisedFrom(t, tenant, tenant+"-alert", detectionv1.Severity_SEVERITY_HIGH, time.Now().UTC())
	if _, err := store.Raise(ctx, []*alertv1.Alert{raised}); err != nil {
		t.Fatalf("raise: %v", err)
	}

	if _, err := store.Move(ctx, raised.GetAlertId(), []string{tenant}, alert.Move{
		To: alert.FalsePositive, Actor: "alice", At: time.Now().UTC(),
	}); !errors.Is(err, alert.ErrNeedsReason) {
		t.Fatalf("a false positive with no reason produced %v", err)
	}

	read, err := store.Alert(ctx, raised.GetAlertId(), []string{tenant})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if read.GetState() != alertv1.State_STATE_OPEN || read.GetRevision() != 1 {
		t.Fatalf("the refused move left the alert %s at revision %d", read.GetState(), read.GetRevision())
	}

	trail, err := store.History(ctx, raised.GetAlertId(), []string{tenant})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if len(trail.GetTransitions()) != 1 {
		t.Fatalf("the refused move left %d lines of trail", len(trail.GetTransitions()))
	}
}

func TestAnAlertIsNeverReadOutsideItsTenant(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx := context.Background()

	tenant := isolated(t)
	raised := raisedFrom(t, tenant, tenant+"-alert", detectionv1.Severity_SEVERITY_HIGH, time.Now().UTC())
	if _, err := store.Raise(ctx, []*alertv1.Alert{raised}); err != nil {
		t.Fatalf("raise: %v", err)
	}

	if _, err := store.Alert(ctx, raised.GetAlertId(), []string{"somebody-else"}); !errors.Is(err, alert.ErrUnknownAlert) {
		t.Fatalf("reading out of scope produced %v", err)
	}
	if _, err := store.History(ctx, raised.GetAlertId(), []string{"somebody-else"}); !errors.Is(err, alert.ErrUnknownAlert) {
		t.Fatalf("reading a trail out of scope produced %v", err)
	}
	if _, err := store.Move(ctx, raised.GetAlertId(), []string{"somebody-else"}, alert.Move{
		To: alert.Acknowledged, Actor: "mallory", At: time.Now().UTC(),
	}); !errors.Is(err, alert.ErrUnknownAlert) {
		t.Fatalf("moving out of scope produced %v", err)
	}

	page, err := store.Page(ctx, &alertv1.Query{}, []string{"somebody-else"})
	if err != nil {
		t.Fatalf("list out of scope: %v", err)
	}
	for _, one := range page.GetAlerts() {
		if one.GetAlertId() == raised.GetAlertId() {
			t.Fatal("a listing out of scope returned the alert")
		}
	}
}

func TestAPageIsNewestFirstAndTheCursorWalksTheRestOfIt(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx := context.Background()

	tenant := isolated(t)
	base := time.Now().UTC().Truncate(time.Millisecond)
	for index := range 5 {
		raised := raisedFrom(t, tenant, tenant+"-alert-"+string(rune('a'+index)),
			detectionv1.Severity_SEVERITY_HIGH, base.Add(time.Duration(index)*time.Second))
		if _, err := store.Raise(ctx, []*alertv1.Alert{raised}); err != nil {
			t.Fatalf("raise: %v", err)
		}
	}

	var walked []string
	cursor := ""
	for range 5 {
		page, err := store.Page(ctx, &alertv1.Query{Limit: 2, Cursor: cursor}, []string{tenant})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, one := range page.GetAlerts() {
			walked = append(walked, one.GetAlertId())
		}
		cursor = page.GetNextCursor()
		if cursor == "" {
			break
		}
	}

	if len(walked) != 5 {
		t.Fatalf("the cursor walked %d alerts of 5", len(walked))
	}
	for index := 1; index < len(walked); index++ {
		if walked[index] >= walked[index-1] {
			t.Fatalf("the page is not newest first: %v", walked)
		}
	}

	if _, err := store.Page(ctx, &alertv1.Query{Cursor: "not-a-cursor"}, []string{tenant}); !errors.Is(err, alert.ErrCursor) {
		t.Fatalf("a composed cursor produced %v", err)
	}
}

func TestAListingAnswersTheQuestionAnOperatorActuallyAsks(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx := context.Background()

	tenant := isolated(t)
	at := time.Now().UTC()
	high := raisedFrom(t, tenant, tenant+"-high", detectionv1.Severity_SEVERITY_HIGH, at)
	medium := raisedFrom(t, tenant, tenant+"-medium", detectionv1.Severity_SEVERITY_MEDIUM, at.Add(-time.Minute))
	if _, err := store.Raise(ctx, []*alertv1.Alert{high, medium}); err != nil {
		t.Fatalf("raise: %v", err)
	}
	if _, err := store.Move(ctx, high.GetAlertId(), []string{tenant}, alert.Move{
		Assignee: alert.Assigning("integration-responder"), Actor: "integration-responder", At: at,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}

	for name, asked := range map[string]*alertv1.Query{
		"by severity": {Severities: []detectionv1.Severity{detectionv1.Severity_SEVERITY_HIGH}},
		"by state":    {States: []alertv1.State{alertv1.State_STATE_OPEN}, Severities: []detectionv1.Severity{detectionv1.Severity_SEVERITY_HIGH}},
		"by holder":   {Assignee: "integration-responder"},
		"by rule":     {RuleId: "ssh.failed_password_from_outside", Severities: []detectionv1.Severity{detectionv1.Severity_SEVERITY_HIGH}},
		"by agent":    {AgentId: "integration-agent", Severities: []detectionv1.Severity{detectionv1.Severity_SEVERITY_HIGH}},
	} {
		page, err := store.Page(ctx, asked, []string{tenant})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(page.GetAlerts()) != 1 || page.GetAlerts()[0].GetAlertId() != high.GetAlertId() {
			t.Errorf("%s returned %d alerts", name, len(page.GetAlerts()))
		}
	}

	page, err := store.Page(ctx, &alertv1.Query{}, []string{tenant})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.GetAlerts()) != 2 {
		t.Fatalf("an unfiltered listing returned %d alerts", len(page.GetAlerts()))
	}
}

type oneBatch struct{ records []alertstore.Record }

func (o oneBatch) Consume(ctx context.Context, deliver alertstore.Deliver) error {
	return deliver(ctx, o.records)
}

func TestTheWriterTurnsRealDetectionsIntoWorkAndReplayingThemAddsNothing(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	tenant := isolated(t)
	at := time.Now().UTC().Truncate(time.Millisecond)

	records := make([]alertstore.Record, 0, 3)
	for name, severity := range map[string]detectionv1.Severity{
		"low":      detectionv1.Severity_SEVERITY_LOW,
		"medium":   detectionv1.Severity_SEVERITY_MEDIUM,
		"critical": detectionv1.Severity_SEVERITY_CRITICAL,
	} {
		encoded, err := proto.Marshal(&detectionv1.Detection{
			DetectionId: tenant + "-" + name,
			Rule:        &detectionv1.Rule{Id: "ssh.failed_password_from_outside", Revision: 3, Name: "Failed SSH password"},
			Severity:    severity,
			EventClass:  eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
			Origin:      &eventv1.Origin{TenantId: tenant, AgentId: "integration-agent"},
			EventTime:   timestamppb.New(at),
		})
		if err != nil {
			t.Fatalf("encode a detection: %v", err)
		}
		records = append(records, alertstore.Record{Key: []byte("integration-agent"), Value: encoded})
	}
	records = append(records, alertstore.Record{Key: []byte("integration-agent"), Value: []byte("not a detection")})

	build := func() *alertstore.Writer {
		writer, err := alertstore.NewWriter(alertstore.WriterOptions{
			Source:        oneBatch{records: records},
			Sink:          store,
			Floor:         detectionv1.Severity_SEVERITY_MEDIUM,
			Metrics:       alertstore.NewMetrics(metrics.New("integration-alerts")),
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

	page, err := store.Page(ctx, &alertv1.Query{}, []string{tenant})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.GetAlerts()) != 2 {
		t.Fatalf("the batch left %d alerts, want the two that cleared the floor", len(page.GetAlerts()))
	}
	for _, one := range page.GetAlerts() {
		if one.GetState() != alertv1.State_STATE_OPEN || one.GetRevision() != 1 {
			t.Errorf("%s arrived %s at revision %d", one.GetAlertId(), one.GetState(), one.GetRevision())
		}
		if one.GetSeverity() == detectionv1.Severity_SEVERITY_LOW {
			t.Errorf("%s is below the floor and became work anyway", one.GetAlertId())
		}
	}

	if err := build().Run(ctx); err != nil {
		t.Fatalf("replay the batch: %v", err)
	}
	replayed, err := store.Page(ctx, &alertv1.Query{}, []string{tenant})
	if err != nil {
		t.Fatalf("list after replay: %v", err)
	}
	if len(replayed.GetAlerts()) != 2 {
		t.Fatalf("replaying the batch left %d alerts", len(replayed.GetAlerts()))
	}
}
