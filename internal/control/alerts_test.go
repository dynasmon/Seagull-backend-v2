package control_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

const raised = "bc84b318fe13e6f6ad86d64da0730a07"

// Enough of an alert store to prove the routes: what the listener owns is who
// may ask, whose alert it is, and which status an answer arrives at. Whether the
// move is legal is the domain's, and this calls the same function the store does.
type stubAlerts struct {
	held      map[string]*alertv1.Alert
	trail     map[string][]*alertv1.Transition
	unreached error
	scoped    [][]string
}

func newStubAlerts() *stubAlerts {
	return &stubAlerts{
		held: map[string]*alertv1.Alert{raised: {
			AlertId:     raised,
			TenantId:    "default",
			DetectionId: raised,
			Rule:        &detectionv1.Rule{Id: "ssh_password_failure", Revision: 1},
			Severity:    detectionv1.Severity_SEVERITY_MEDIUM,
			State:       alertv1.State_STATE_OPEN,
			RaisedAt:    timestamppb.New(time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)),
			ChangedBy:   alert.Platform,
			ChangedAt:   timestamppb.New(time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)),
			Revision:    1,
		}},
		trail: map[string][]*alertv1.Transition{},
	}
}

func (s *stubAlerts) Page(_ context.Context, _ *alertv1.Query, tenants []string) (*alertv1.Page, error) {
	s.scoped = append(s.scoped, tenants)
	if s.unreached != nil {
		return nil, s.unreached
	}
	page := &alertv1.Page{}
	for _, one := range s.held {
		if slices.Contains(tenants, one.GetTenantId()) {
			page.Alerts = append(page.Alerts, one)
		}
	}
	return page, nil
}

func (s *stubAlerts) Alert(_ context.Context, id string, tenants []string) (*alertv1.Alert, error) {
	s.scoped = append(s.scoped, tenants)
	if s.unreached != nil {
		return nil, s.unreached
	}
	one, known := s.held[id]
	if !known || !slices.Contains(tenants, one.GetTenantId()) {
		return nil, alert.ErrUnknownAlert
	}
	return one, nil
}

func (s *stubAlerts) History(ctx context.Context, id string, tenants []string) (*alertv1.History, error) {
	if _, err := s.Alert(ctx, id, tenants); err != nil {
		return nil, err
	}
	return &alertv1.History{AlertId: id, Transitions: s.trail[id]}, nil
}

func (s *stubAlerts) Move(ctx context.Context, id string, tenants []string, asked alert.Move) (*alertv1.Alert, error) {
	current, err := s.Alert(ctx, id, tenants)
	if err != nil {
		return nil, err
	}
	moved, line, err := alert.Apply(current, asked)
	if err != nil {
		return nil, err
	}
	s.held[id] = moved
	s.trail[id] = append(s.trail[id], line)
	return moved, nil
}

func alerts(t *testing.T, h *harness, store *stubAlerts) http.Handler {
	t.Helper()
	return listener(t, h, newStubRulesets(), store)
}

func TestReadingAnAlertNeedsThePermissionAndMovingOneNeedsMore(t *testing.T) {
	h := newHarness(t, nil)
	handler := alerts(t, h, newStubAlerts())

	analyst := session(t, handler, "dev-analyst")
	if recorder := call(t, handler, http.MethodGet, "/v1/alerts/"+raised, "dev-analyst", analyst, nil); recorder.Code != http.StatusOK {
		t.Fatalf("reading an alert answered an analyst %d: %s", recorder.Code, recorder.Body)
	}

	recorder := call(t, handler, http.MethodPost, "/v1/alerts/"+raised+"/transition", "dev-analyst", analyst,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_ACKNOWLEDGED})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("an analyst moved an alert: %d", recorder.Code)
	}

	engineer := session(t, handler, "dev-engineer")
	if recorder := call(t, handler, http.MethodGet, "/v1/alerts/"+raised, "dev-engineer", engineer, nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("an engineer read an alert: %d", recorder.Code)
	}
}

func TestAnAlertIsAnsweredWithinTheTenantsThePolicyGranted(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubAlerts()
	handler := alerts(t, h, store)

	analyst := session(t, handler, "dev-analyst")
	if recorder := call(t, handler, http.MethodPost, control.AlertSearch, "dev-analyst", analyst, &alertv1.Query{}); recorder.Code != http.StatusOK {
		t.Fatalf("searching alerts answered %d: %s", recorder.Code, recorder.Body)
	}
	if len(store.scoped) == 0 {
		t.Fatal("the listener answered without passing a scope to the store")
	}
	for _, scope := range store.scoped {
		if !slices.Equal(scope, []string{"default"}) {
			t.Errorf("the store was asked within %v", scope)
		}
	}

	elsewhere := store.held[raised]
	elsewhere.TenantId = "another-tenant"
	recorder := call(t, handler, http.MethodGet, "/v1/alerts/"+raised, "dev-analyst", analyst, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("an alert in another tenant answered %d, wanted 404", recorder.Code)
	}
}

func TestTriageRunsThroughTheApiAndTheTrailRecordsWhoDidIt(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubAlerts()
	handler := alerts(t, h, store)
	responder := session(t, handler, "dev-responder")

	for _, step := range []struct {
		to   alertv1.State
		note string
	}{
		{alertv1.State_STATE_ACKNOWLEDGED, ""},
		{alertv1.State_STATE_IN_INVESTIGATION, ""},
		{alertv1.State_STATE_FALSE_POSITIVE, "the scanner is ours"},
	} {
		recorder := call(t, handler, http.MethodPost, "/v1/alerts/"+raised+"/transition", "dev-responder", responder,
			&alertv1.TransitionRequest{To: step.to, Note: step.note})
		if recorder.Code != http.StatusOK {
			t.Fatalf("moving to %s answered %d: %s", step.to, recorder.Code, recorder.Body)
		}

		var answer alertv1.Alert
		decode(t, recorder, &answer)
		if answer.GetState() != step.to {
			t.Fatalf("the alert became %s", answer.GetState())
		}
		if answer.GetChangedBy() != "dev-responder" {
			t.Errorf("the move was attributed to %q", answer.GetChangedBy())
		}
	}

	recorder := call(t, handler, http.MethodGet, "/v1/alerts/"+raised+"/history", "dev-responder", responder, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("reading the trail answered %d", recorder.Code)
	}
	var history alertv1.History
	decode(t, recorder, &history)
	if len(history.GetTransitions()) != 3 {
		t.Fatalf("the trail carries %d lines", len(history.GetTransitions()))
	}
	for _, line := range history.GetTransitions() {
		if line.GetActor() != "dev-responder" {
			t.Errorf("a line of the trail is attributed to %q", line.GetActor())
		}
	}
}

func TestAnIllegalMoveIsRefusedAtTheApiAndTheAlertDoesNotMove(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubAlerts()
	handler := alerts(t, h, store)
	responder := session(t, handler, "dev-responder")

	recorder := call(t, handler, http.MethodPost, "/v1/alerts/"+raised+"/transition", "dev-responder", responder,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_FALSE_POSITIVE})
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a false positive with no reason answered %d, wanted 422", recorder.Code)
	}
	if refusal := refusalOf(t, recorder); refusal.GetCode() != control.CodeIllegalMove {
		t.Errorf("it was refused %q", refusal.GetCode())
	}
	if store.held[raised].GetState() != alertv1.State_STATE_OPEN {
		t.Fatal("a refused move changed the alert")
	}

	recorder = call(t, handler, http.MethodPost, "/v1/alerts/"+raised+"/transition", "dev-responder", responder,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_UNSPECIFIED})
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a move naming no state answered %d", recorder.Code)
	}
}

func TestActingOnAnAlertSomebodyElseHoldsNeedsMoreThanWriting(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubAlerts()
	handler := alerts(t, h, store)

	responder := session(t, handler, "dev-responder")
	recorder := call(t, handler, http.MethodPost, "/v1/alerts/"+raised+"/assignment", "dev-responder", responder,
		&alertv1.AssignmentRequest{Assignee: "dev-admin"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("handing the alert over answered %d: %s", recorder.Code, recorder.Body)
	}

	recorder = call(t, handler, http.MethodPost, "/v1/alerts/"+raised+"/transition", "dev-responder", responder,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_ACKNOWLEDGED})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("a responder acted on somebody else's alert: %d", recorder.Code)
	}
	if refusal := refusalOf(t, recorder); refusal.GetCode() != control.CodeHeldByAnother {
		t.Errorf("it was refused %q", refusal.GetCode())
	}

	administrator := session(t, handler, "dev-admin")
	recorder = call(t, handler, http.MethodPost, "/v1/alerts/"+raised+"/transition", "dev-admin", administrator,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_ACKNOWLEDGED})
	if recorder.Code != http.StatusOK {
		t.Fatalf("an administrator holding alerts:delete was refused %d: %s", recorder.Code, recorder.Body)
	}
}

func TestAStaleRevisionIsRefusedRatherThanOverwritingTheOtherPerson(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubAlerts()
	handler := alerts(t, h, store)
	responder := session(t, handler, "dev-responder")

	if recorder := call(t, handler, http.MethodPost, "/v1/alerts/"+raised+"/transition", "dev-responder", responder,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_ACKNOWLEDGED, ExpectedRevision: 1}); recorder.Code != http.StatusOK {
		t.Fatalf("the first move answered %d", recorder.Code)
	}

	recorder := call(t, handler, http.MethodPost, "/v1/alerts/"+raised+"/transition", "dev-responder", responder,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_IN_INVESTIGATION, ExpectedRevision: 1})
	if recorder.Code != http.StatusConflict {
		t.Fatalf("a stale revision answered %d, wanted 409", recorder.Code)
	}
	if refusal := refusalOf(t, recorder); refusal.GetCode() != control.CodeAlertMoved {
		t.Errorf("it was refused %q", refusal.GetCode())
	}
}

func TestAStoreThatDoesNotAnswerIsNotACallerMistake(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubAlerts()
	store.unreached = errors.New("the alert store is not answering")
	handler := alerts(t, h, store)

	analyst := session(t, handler, "dev-analyst")
	recorder := call(t, handler, http.MethodPost, control.AlertSearch, "dev-analyst", analyst, &alertv1.Query{})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unreachable store answered %d, wanted 503", recorder.Code)
	}
	if refusal := refusalOf(t, recorder); refusal.GetCode() != control.CodeAlertsUnavailable {
		t.Errorf("it was refused %q", refusal.GetCode())
	}
}

func refusalOf(t *testing.T, recorder *httptest.ResponseRecorder) *controlv1.Refusal {
	t.Helper()
	var refusal controlv1.Refusal
	decode(t, recorder, &refusal)
	return &refusal
}
