package e2e_test

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

const openIncident = "3f9c1d77a4e0b25518c6d4a90ee3b710"

func decode(t *testing.T, body []byte, into proto.Message) {
	t.Helper()
	if err := proto.Unmarshal(body, into); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
}

type openedIncidents struct {
	mutex sync.Mutex
	held  map[string]*incidentv1.Incident
	trail map[string][]*incidentv1.Transition
}

func newOpenedIncidents() *openedIncidents {
	failed := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)
	told, err := incident.Raise(&detectionv1.Detection{
		DetectionId: openIncident,
		Rule: &detectionv1.Rule{
			Id: "ssh.password_guessing_that_succeeded", Revision: 1,
			Name: "SSH password guessing that succeeded",
		},
		RulesetId:  "89ab5f2c",
		Severity:   detectionv1.Severity_SEVERITY_CRITICAL,
		EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Origin:     &eventv1.Origin{TenantId: "default", AgentId: "e2e-agent-01"},
		Correlation: &detectionv1.Correlation{
			Stages: []*detectionv1.Stage{
				{Name: "a failed password", EventId: "e2e-event-1", EventTime: timestamppb.New(failed)},
				{Name: "one that was accepted", EventId: "e2e-event-2", EventTime: timestamppb.New(failed.Add(40 * time.Second))},
			},
			Window:      durationpb.New(5 * time.Minute),
			ClockSpread: durationpb.New(0),
			Group:       []*detectionv1.Grouping{{Field: "origin.agent_id", Value: "e2e-agent-01"}},
		},
	}, failed.Add(time.Minute))
	if err != nil {
		panic(err)
	}
	return &openedIncidents{
		held:  map[string]*incidentv1.Incident{openIncident: told},
		trail: map[string][]*incidentv1.Transition{openIncident: {incident.Raised(told)}},
	}
}

func (o *openedIncidents) Page(_ context.Context, _ *incidentv1.Query, tenants []string) (*incidentv1.Page, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	page := &incidentv1.Page{}
	for _, one := range o.held {
		if slices.Contains(tenants, one.GetTenantId()) {
			page.Incidents = append(page.Incidents, one)
		}
	}
	return page, nil
}

func (o *openedIncidents) Incident(_ context.Context, id string, tenants []string) (*incidentv1.Incident, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.read(id, tenants)
}

func (o *openedIncidents) read(id string, tenants []string) (*incidentv1.Incident, error) {
	one, known := o.held[id]
	if !known || !slices.Contains(tenants, one.GetTenantId()) {
		return nil, incident.ErrUnknownIncident
	}
	return one, nil
}

func (o *openedIncidents) History(_ context.Context, id string, tenants []string) (*incidentv1.History, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if _, err := o.read(id, tenants); err != nil {
		return nil, err
	}
	return &incidentv1.History{IncidentId: id, Transitions: o.trail[id]}, nil
}

func (o *openedIncidents) Move(_ context.Context, id string, tenants []string, asked incident.Move) (*incidentv1.Incident, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	current, err := o.read(id, tenants)
	if err != nil {
		return nil, err
	}
	moved, line, err := incident.Apply(current, asked)
	if err != nil {
		return nil, err
	}
	o.held[id] = moved
	o.trail[id] = append(o.trail[id], line)
	return moved, nil
}

func TestAnIncidentIsWorkedOverRealMutualTLSAndTracesBackToItsEvents(t *testing.T) {
	plane := startControlAPI(t, nil)
	responder := plane.caller(t, "e2e-responder")
	token := plane.open(t, responder).GetToken()

	response, body := plane.send(t, responder, http.MethodGet, "/v1/incidents/"+openIncident, token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reading the incident answered %d: %s", response.StatusCode, body)
	}
	var told incidentv1.Incident
	decode(t, body, &told)

	if told.GetDetectionId() != openIncident {
		t.Errorf("the incident does not name the detection that told it: %q", told.GetDetectionId())
	}
	if len(told.GetStages()) != 2 {
		t.Fatalf("the story carries %d stages", len(told.GetStages()))
	}
	for index, wanted := range []string{"e2e-event-1", "e2e-event-2"} {
		if told.GetStages()[index].GetEventId() != wanted {
			t.Errorf("stage %d names %q rather than %q", index, told.GetStages()[index].GetEventId(), wanted)
		}
	}
	if told.GetConfidence() != incidentv1.Confidence_CONFIDENCE_HIGH {
		t.Errorf("the story was opened at %s", incident.Level(told.GetConfidence()))
	}

	for _, step := range []*incidentv1.TransitionRequest{
		{To: incidentv1.State_STATE_ACKNOWLEDGED},
		{To: incidentv1.State_STATE_IN_INVESTIGATION, Note: "checking what the session did after it was accepted"},
		{To: incidentv1.State_STATE_RESOLVED, Note: "the account was rotated"},
	} {
		response, body := plane.send(t, responder, http.MethodPost,
			"/v1/incidents/"+openIncident+"/transition", token, step)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("moving to %s answered %d: %s", step.GetTo(), response.StatusCode, body)
		}
	}

	response, body = plane.send(t, responder, http.MethodGet, "/v1/incidents/"+openIncident+"/history", token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reading the trail answered %d: %s", response.StatusCode, body)
	}
	var trail incidentv1.History
	decode(t, body, &trail)
	if len(trail.GetTransitions()) != 4 {
		t.Fatalf("opening and three moves left %d lines of trail", len(trail.GetTransitions()))
	}
	for _, line := range trail.GetTransitions() {
		if line.GetActor() == "" {
			t.Errorf("revision %d says nobody did it", line.GetRevision())
		}
	}

	response, body = plane.send(t, responder, http.MethodGet, "/v1/incidents/"+openIncident, token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reading the closed incident answered %d: %s", response.StatusCode, body)
	}
	var closed incidentv1.Incident
	decode(t, body, &closed)
	if len(closed.GetStages()) != len(told.GetStages()) {
		t.Fatal("working the story changed what it is made of")
	}
	if closed.GetStages()[0].GetEventId() != told.GetStages()[0].GetEventId() {
		t.Error("working the story changed which events it names")
	}
}

func TestAnAnalystReadsAStoryAndCannotWorkIt(t *testing.T) {
	plane := startControlAPI(t, nil)
	analyst := plane.caller(t, "e2e-analyst")
	token := plane.open(t, analyst).GetToken()

	response, body := plane.send(t, analyst, http.MethodGet, "/v1/incidents/"+openIncident, token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reading the incident answered an analyst %d: %s", response.StatusCode, body)
	}

	response, _ = plane.send(t, analyst, http.MethodPost, "/v1/incidents/"+openIncident+"/transition", token,
		&incidentv1.TransitionRequest{To: incidentv1.State_STATE_ACKNOWLEDGED})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("an analyst moved an incident: %d", response.StatusCode)
	}
}
