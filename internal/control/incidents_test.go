package control_test

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

const correlated = "3f9c1d77a4e0b25518c6d4a90ee3b710"

// Enough of an incident store to prove the routes: what the listener owns is
// who may ask, whose story it is, and which status an answer arrives at.
type stubIncidents struct {
	held      map[string]*incidentv1.Incident
	trail     map[string][]*incidentv1.Transition
	unreached error
	scoped    [][]string
}

func newStubIncidents() *stubIncidents {
	told := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)
	return &stubIncidents{
		held: map[string]*incidentv1.Incident{correlated: {
			IncidentId:  correlated,
			TenantId:    "default",
			DetectionId: correlated,
			Rule:        &detectionv1.Rule{Id: "ssh.password_guessing_that_succeeded", Revision: 1},
			Severity:    detectionv1.Severity_SEVERITY_CRITICAL,
			Confidence:  incidentv1.Confidence_CONFIDENCE_HIGH,
			Stages: []*detectionv1.Stage{
				{Name: "a failed password", EventId: "event-1", EventTime: timestamppb.New(told)},
				{Name: "one that was accepted", EventId: "event-2", EventTime: timestamppb.New(told.Add(40 * time.Second))},
			},
			Window:         durationpb.New(5 * time.Minute),
			FirstEventTime: timestamppb.New(told),
			LastEventTime:  timestamppb.New(told.Add(40 * time.Second)),
			State:          incidentv1.State_STATE_OPEN,
			RaisedAt:       timestamppb.New(told.Add(time.Minute)),
			ChangedBy:      incident.Platform,
			ChangedAt:      timestamppb.New(told.Add(time.Minute)),
			Revision:       1,
		}},
		trail: map[string][]*incidentv1.Transition{},
	}
}

func (s *stubIncidents) Page(_ context.Context, _ *incidentv1.Query, tenants []string) (*incidentv1.Page, error) {
	s.scoped = append(s.scoped, tenants)
	if s.unreached != nil {
		return nil, s.unreached
	}
	page := &incidentv1.Page{}
	for _, one := range s.held {
		if slices.Contains(tenants, one.GetTenantId()) {
			page.Incidents = append(page.Incidents, one)
		}
	}
	return page, nil
}

func (s *stubIncidents) Incident(_ context.Context, id string, tenants []string) (*incidentv1.Incident, error) {
	s.scoped = append(s.scoped, tenants)
	if s.unreached != nil {
		return nil, s.unreached
	}
	one, known := s.held[id]
	if !known || !slices.Contains(tenants, one.GetTenantId()) {
		return nil, incident.ErrUnknownIncident
	}
	return one, nil
}

func (s *stubIncidents) History(ctx context.Context, id string, tenants []string) (*incidentv1.History, error) {
	if _, err := s.Incident(ctx, id, tenants); err != nil {
		return nil, err
	}
	return &incidentv1.History{IncidentId: id, Transitions: s.trail[id]}, nil
}

func (s *stubIncidents) Move(ctx context.Context, id string, tenants []string, asked incident.Move) (*incidentv1.Incident, error) {
	current, err := s.Incident(ctx, id, tenants)
	if err != nil {
		return nil, err
	}
	moved, line, err := incident.Apply(current, asked)
	if err != nil {
		return nil, err
	}
	s.held[id] = moved
	s.trail[id] = append(s.trail[id], line)
	return moved, nil
}

func incidents(t *testing.T, h *harness, told *stubIncidents) http.Handler {
	t.Helper()
	return listenerTelling(t, h, newStubRulesets(), newStubAlerts(), told)
}

func TestReadingAnIncidentIsGrantedApartFromReadingAnAlert(t *testing.T) {
	h := newHarness(t, nil)
	handler := incidents(t, h, newStubIncidents())

	analyst := session(t, handler, "dev-analyst")
	if recorder := call(t, handler, http.MethodGet, "/v1/incidents/"+correlated, "dev-analyst", analyst, nil); recorder.Code != http.StatusOK {
		t.Fatalf("reading an incident answered an analyst %d: %s", recorder.Code, recorder.Body)
	}

	recorder := call(t, handler, http.MethodPost, "/v1/incidents/"+correlated+"/transition", "dev-analyst", analyst,
		&incidentv1.TransitionRequest{To: incidentv1.State_STATE_ACKNOWLEDGED})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("an analyst moved an incident: %d", recorder.Code)
	}

	engineer := session(t, handler, "dev-engineer")
	if recorder := call(t, handler, http.MethodGet, "/v1/incidents/"+correlated, "dev-engineer", engineer, nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("an engineer with no incident grant read one: %d", recorder.Code)
	}
}

func TestAStoryIsWorkedThroughItsOwnLifecycleAndTheTrailFollows(t *testing.T) {
	h := newHarness(t, nil)
	told := newStubIncidents()
	handler := incidents(t, h, told)

	responder := session(t, handler, "dev-responder")
	for _, step := range []*incidentv1.TransitionRequest{
		{To: incidentv1.State_STATE_ACKNOWLEDGED},
		{To: incidentv1.State_STATE_IN_INVESTIGATION},
		{To: incidentv1.State_STATE_RESOLVED},
	} {
		recorder := call(t, handler, http.MethodPost, "/v1/incidents/"+correlated+"/transition", "dev-responder", responder, step)
		if recorder.Code != http.StatusOK {
			t.Fatalf("moving to %s answered %d: %s", step.GetTo(), recorder.Code, recorder.Body)
		}
	}

	if state := told.held[correlated].GetState(); state != incidentv1.State_STATE_RESOLVED {
		t.Fatalf("the incident ended at %s", state)
	}
	if len(told.trail[correlated]) != 3 {
		t.Fatalf("three moves left %d lines of trail", len(told.trail[correlated]))
	}

	recorder := call(t, handler, http.MethodGet, "/v1/incidents/"+correlated+"/history", "dev-responder", responder, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("reading the trail answered %d: %s", recorder.Code, recorder.Body)
	}
}

func TestWorkingAStoryChangesNothingAboutWhatItIsMadeOf(t *testing.T) {
	h := newHarness(t, nil)
	told := newStubIncidents()
	handler := incidents(t, h, told)

	before := told.held[correlated]
	stages := slices.Clone(before.GetStages())

	responder := session(t, handler, "dev-responder")
	recorder := call(t, handler, http.MethodPost, "/v1/incidents/"+correlated+"/transition", "dev-responder", responder,
		&incidentv1.TransitionRequest{To: incidentv1.State_STATE_FALSE_POSITIVE, Note: "one operator retrying"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("dismissing the story answered %d: %s", recorder.Code, recorder.Body)
	}

	after := told.held[correlated]
	if after.GetDetectionId() != before.GetDetectionId() {
		t.Error("dismissing the story changed what told it")
	}
	if len(after.GetStages()) != len(stages) {
		t.Fatalf("dismissing the story left %d stages", len(after.GetStages()))
	}
	for index, stage := range after.GetStages() {
		if stage.GetEventId() != stages[index].GetEventId() {
			t.Errorf("stage %d names %q", index, stage.GetEventId())
		}
	}
}

func TestAStoryOutsideTheCallersTenantsIsNotThere(t *testing.T) {
	h := newHarness(t, nil)
	told := newStubIncidents()
	told.held[correlated].TenantId = "somebody-else"
	handler := incidents(t, h, told)

	analyst := session(t, handler, "dev-analyst")
	recorder := call(t, handler, http.MethodGet, "/v1/incidents/"+correlated, "dev-analyst", analyst, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("a story in another tenant answered %d", recorder.Code)
	}
	for _, scope := range told.scoped {
		if len(scope) == 0 {
			t.Fatal("an incident was read without a scope")
		}
	}
}

func TestAStoryHeldByAnotherNeedsMoreThanWritingOne(t *testing.T) {
	h := newHarness(t, nil)
	told := newStubIncidents()
	told.held[correlated].Assignee = "dev-admin"
	handler := incidents(t, h, told)

	responder := session(t, handler, "dev-responder")
	recorder := call(t, handler, http.MethodPost, "/v1/incidents/"+correlated+"/transition", "dev-responder", responder,
		&incidentv1.TransitionRequest{To: incidentv1.State_STATE_ACKNOWLEDGED})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("a responder moved somebody else's incident: %d", recorder.Code)
	}

	admin := session(t, handler, "dev-admin")
	if recorder := call(t, handler, http.MethodPost, "/v1/incidents/"+correlated+"/transition", "dev-admin", admin,
		&incidentv1.TransitionRequest{To: incidentv1.State_STATE_ACKNOWLEDGED}); recorder.Code != http.StatusOK {
		t.Fatalf("an administrator was refused somebody else's incident: %d: %s", recorder.Code, recorder.Body)
	}
}

var _ control.Incidents = (*stubIncidents)(nil)
