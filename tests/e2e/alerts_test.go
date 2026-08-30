package e2e_test

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const openAlert = "bc84b318fe13e6f6ad86d64da0730a07"

// The store as far as the listener is concerned: the same domain function the
// relational store calls, so what this proves is the surface — who may ask, the
// scope they are answered within, and the trail — rather than the driver, which
// tests/integration exercises against a real PostgreSQL.
type raisedAlerts struct {
	mutex sync.Mutex
	held  map[string]*alertv1.Alert
	trail map[string][]*alertv1.Transition
	made  map[string][]*alertv1.Occurrence
}

func newRaisedAlerts() *raisedAlerts {
	made, err := alert.Raise(&detectionv1.Detection{
		DetectionId: openAlert,
		Rule:        &detectionv1.Rule{Id: "ssh_password_failure_from_outside", Revision: 1, Name: "SSH password failure"},
		Severity:    detectionv1.Severity_SEVERITY_MEDIUM,
		EventClass:  eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Origin:      &eventv1.Origin{TenantId: "default", AgentId: "e2e-agent-01"},
		EventTime:   timestamppb.New(time.Date(2026, 8, 30, 11, 0, 0, 0, time.UTC)),
	}, time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC))
	if err != nil {
		panic(err)
	}
	return &raisedAlerts{
		held:  map[string]*alertv1.Alert{openAlert: made},
		trail: map[string][]*alertv1.Transition{openAlert: {alert.Raised(made)}},
		made:  map[string][]*alertv1.Occurrence{openAlert: {{DetectionId: openAlert}}},
	}
}

func (r *raisedAlerts) Page(_ context.Context, _ *alertv1.Query, tenants []string) (*alertv1.Page, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	page := &alertv1.Page{}
	for _, one := range r.held {
		if slices.Contains(tenants, one.GetTenantId()) {
			page.Alerts = append(page.Alerts, one)
		}
	}
	return page, nil
}

func (r *raisedAlerts) Alert(_ context.Context, id string, tenants []string) (*alertv1.Alert, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.read(id, tenants)
}

func (r *raisedAlerts) read(id string, tenants []string) (*alertv1.Alert, error) {
	one, known := r.held[id]
	if !known || !slices.Contains(tenants, one.GetTenantId()) {
		return nil, alert.ErrUnknownAlert
	}
	return one, nil
}

func (r *raisedAlerts) History(_ context.Context, id string, tenants []string) (*alertv1.History, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, err := r.read(id, tenants); err != nil {
		return nil, err
	}
	return &alertv1.History{AlertId: id, Transitions: r.trail[id]}, nil
}

func (r *raisedAlerts) Occurrences(_ context.Context, id string, tenants []string) (*alertv1.Occurrences, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, err := r.read(id, tenants); err != nil {
		return nil, err
	}
	return &alertv1.Occurrences{AlertId: id, Occurrences: r.made[id]}, nil
}

func (r *raisedAlerts) Move(_ context.Context, id string, tenants []string, asked alert.Move) (*alertv1.Alert, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	current, err := r.read(id, tenants)
	if err != nil {
		return nil, err
	}
	moved, line, err := alert.Apply(current, asked)
	if err != nil {
		return nil, err
	}
	r.held[id] = moved
	r.trail[id] = append(r.trail[id], line)
	return moved, nil
}

func TestAnAlertIsTriagedOverRealMutualTLSAndEveryStepIsAttributable(t *testing.T) {
	plane := startControlAPI(t, nil)
	responder := plane.caller(t, "e2e-responder")
	token := plane.open(t, responder).GetToken()

	for _, step := range []struct {
		to   alertv1.State
		note string
	}{
		{alertv1.State_STATE_ACKNOWLEDGED, ""},
		{alertv1.State_STATE_IN_INVESTIGATION, "checking whether the source is ours"},
		{alertv1.State_STATE_RESOLVED, "the key was rotated"},
	} {
		response, body := plane.send(t, responder, http.MethodPost, "/v1/alerts/"+openAlert+"/transition", token,
			&alertv1.TransitionRequest{To: step.to, Note: step.note})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("moving to %s answered %d: %s", step.to, response.StatusCode, body)
		}

		var moved alertv1.Alert
		if err := proto.Unmarshal(body, &moved); err != nil {
			t.Fatalf("decode the alert: %v", err)
		}
		if moved.GetState() != step.to || moved.GetChangedBy() != "e2e-responder" {
			t.Fatalf("the alert became %s, changed by %q", moved.GetState(), moved.GetChangedBy())
		}
	}

	response, body := plane.send(t, responder, http.MethodGet, "/v1/alerts/"+openAlert+"/history", token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reading the trail answered %d: %s", response.StatusCode, body)
	}

	var history alertv1.History
	if err := proto.Unmarshal(body, &history); err != nil {
		t.Fatalf("decode the trail: %v", err)
	}
	if len(history.GetTransitions()) != 4 {
		t.Fatalf("the trail carries %d lines", len(history.GetTransitions()))
	}
	if first := history.GetTransitions()[0]; first.GetActor() != alert.Platform {
		t.Errorf("the alert was raised by %q", first.GetActor())
	}
	for _, line := range history.GetTransitions()[1:] {
		if line.GetActor() != "e2e-responder" {
			t.Errorf("a move is attributed to %q", line.GetActor())
		}
	}
}

// Folding raises a count, so the count has to be readable back to the detections
// behind it or suppression has destroyed the evidence an investigation needs.
func TestAnAlertNamesEveryDetectionItIsMadeOf(t *testing.T) {
	plane := startControlAPI(t, nil)
	analyst := plane.caller(t, "e2e-analyst")
	token := plane.open(t, analyst).GetToken()

	response, body := plane.send(t, analyst, http.MethodGet, "/v1/alerts/"+openAlert+"/occurrences", token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reading what the alert is made of answered %d: %s", response.StatusCode, body)
	}

	var made alertv1.Occurrences
	if err := proto.Unmarshal(body, &made); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if made.GetAlertId() != openAlert {
		t.Errorf("it answered about %q", made.GetAlertId())
	}
	if len(made.GetOccurrences()) != 1 {
		t.Fatalf("the alert names %d detections", len(made.GetOccurrences()))
	}

	outsider := plane.caller(t, "e2e-outsider")
	outsiderToken := plane.open(t, outsider).GetToken()
	response, _ = plane.send(t, outsider, http.MethodGet, "/v1/alerts/"+openAlert+"/occurrences", outsiderToken, nil)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("a caller in another tenant read what the alert is made of: %d", response.StatusCode)
	}
}

func TestReopeningAndClosingAsAFalsePositiveAreDifferentActs(t *testing.T) {
	plane := startControlAPI(t, nil)
	responder := plane.caller(t, "e2e-responder")
	token := plane.open(t, responder).GetToken()

	response, body := plane.send(t, responder, http.MethodPost, "/v1/alerts/"+openAlert+"/transition", token,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_FALSE_POSITIVE})
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a false positive with no reason answered %d: %s", response.StatusCode, body)
	}
	if code := refusalCode(t, body); code != control.CodeIllegalMove {
		t.Errorf("it was refused %q", code)
	}

	response, body = plane.send(t, responder, http.MethodPost, "/v1/alerts/"+openAlert+"/transition", token,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_FALSE_POSITIVE, Note: "the scanner is ours"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("closing as a false positive answered %d: %s", response.StatusCode, body)
	}

	var closed alertv1.Alert
	if err := proto.Unmarshal(body, &closed); err != nil {
		t.Fatalf("decode the alert: %v", err)
	}
	if closed.GetClosure().GetState() != alertv1.State_STATE_FALSE_POSITIVE {
		t.Fatalf("it closed as %s", closed.GetClosure().GetState())
	}
	if closed.GetClosure().GetReason() != "the scanner is ours" {
		t.Errorf("the reason was kept as %q", closed.GetClosure().GetReason())
	}

	response, body = plane.send(t, responder, http.MethodPost, "/v1/alerts/"+openAlert+"/transition", token,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_RESOLVED, Note: "on reflection it was real"})
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("closing a closed alert a second way answered %d: %s", response.StatusCode, body)
	}

	response, body = plane.send(t, responder, http.MethodPost, "/v1/alerts/"+openAlert+"/transition", token,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_OPEN, Note: "the scanner was not ours after all"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reopening answered %d: %s", response.StatusCode, body)
	}

	var reopened alertv1.Alert
	if err := proto.Unmarshal(body, &reopened); err != nil {
		t.Fatalf("decode the alert: %v", err)
	}
	if reopened.GetClosure() != nil {
		t.Error("a reopened alert still carries the closure that ended it")
	}
}

func TestAnAlertIsOnlyEverAnsweredWithinTheTenantsThePolicyGranted(t *testing.T) {
	plane := startControlAPI(t, nil)
	outsider := plane.caller(t, "e2e-outsider")
	token := plane.open(t, outsider).GetToken()

	response, body := plane.send(t, outsider, http.MethodGet, "/v1/alerts/"+openAlert, token, nil)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("a caller bound to another tenant read the alert: %d %s", response.StatusCode, body)
	}
	if code := refusalCode(t, body); code != control.CodeUnknownAlert {
		t.Errorf("it was refused %q", code)
	}

	response, body = plane.send(t, outsider, http.MethodPost, control.AlertSearch, token, &alertv1.Query{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("searching answered %d: %s", response.StatusCode, body)
	}
	var page alertv1.Page
	if err := proto.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode the page: %v", err)
	}
	if len(page.GetAlerts()) != 0 {
		t.Fatalf("a caller in another tenant was shown %d alerts", len(page.GetAlerts()))
	}
}

func TestAnAlertHeldByOneResponderIsNotMovedByAnother(t *testing.T) {
	plane := startControlAPI(t, nil)

	responder := plane.caller(t, "e2e-responder")
	responderToken := plane.open(t, responder).GetToken()
	response, body := plane.send(t, responder, http.MethodPost, "/v1/alerts/"+openAlert+"/assignment", responderToken,
		&alertv1.AssignmentRequest{Assignee: "e2e-responder"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("taking the alert answered %d: %s", response.StatusCode, body)
	}

	colleague := plane.caller(t, "e2e-colleague")
	colleagueToken := plane.open(t, colleague).GetToken()
	response, body = plane.send(t, colleague, http.MethodPost, "/v1/alerts/"+openAlert+"/transition", colleagueToken,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_ACKNOWLEDGED})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("a second responder moved an alert somebody else holds: %d %s", response.StatusCode, body)
	}
	if code := refusalCode(t, body); code != control.CodeHeldByAnother {
		t.Errorf("it was refused %q", code)
	}

	analyst := plane.caller(t, "e2e-analyst")
	analystToken := plane.open(t, analyst).GetToken()
	response, body = plane.send(t, analyst, http.MethodPost, "/v1/alerts/"+openAlert+"/transition", analystToken,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_ACKNOWLEDGED})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("an analyst moved an alert: %d %s", response.StatusCode, body)
	}

	administrator := plane.caller(t, "e2e-admin")
	adminToken := plane.open(t, administrator).GetToken()
	response, body = plane.send(t, administrator, http.MethodPost, "/v1/alerts/"+openAlert+"/transition", adminToken,
		&alertv1.TransitionRequest{To: alertv1.State_STATE_ACKNOWLEDGED})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("an administrator holding alerts:delete was refused %d: %s", response.StatusCode, body)
	}
}
