package control_test

import (
	"net/http"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
	"google.golang.org/protobuf/proto"
)

// A store builds its predicate from the values it recognises, so a filter it
// recognises nothing in becomes no filter and the listing widens to everything
// the caller may read. Asking for a state that does not exist is a mistake the
// caller is told about rather than one answered with more than they asked for.
func TestAListingRefusesAFilterTheContractDoesNotDeclare(t *testing.T) {
	cases := map[string]struct {
		path    string
		asked   proto.Message
		holder  string
		serving func(t *testing.T, h *harness) http.Handler
	}{
		"alert state": {
			control.AlertSearch,
			&alertv1.Query{States: []alertv1.State{alertv1.State(99)}},
			"dev-analyst",
			servingAlerts,
		},
		"alert severity": {
			control.AlertSearch,
			&alertv1.Query{Severities: []detectionv1.Severity{detectionv1.Severity(99)}},
			"dev-analyst",
			servingAlerts,
		},
		"incident state": {
			control.IncidentSearch,
			&incidentv1.Query{States: []incidentv1.State{incidentv1.State(99)}},
			"dev-analyst",
			servingIncidents,
		},
		"incident confidence": {
			control.IncidentSearch,
			&incidentv1.Query{Confidences: []incidentv1.Confidence{incidentv1.Confidence(99)}},
			"dev-analyst",
			servingIncidents,
		},
		"agent state": {
			control.AgentSearch,
			&agentv1.Query{States: []agentv1.State{agentv1.State(99)}},
			"dev-admin",
			servingAgents,
		},
	}

	for name, held := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			handler := held.serving(t, h)

			token := session(t, handler, held.holder)
			recorder := call(t, handler, http.MethodPost, held.path, held.holder, token, held.asked)
			if recorder.Code != http.StatusUnprocessableEntity {
				t.Fatalf("a filter the contract does not declare answered %d, wanted 422", recorder.Code)
			}
			if refusal := refusalOf(t, recorder); refusal.GetCode() != control.CodeUnknownFilter {
				t.Errorf("it was refused %q", refusal.GetCode())
			}
		})
	}
}

// The values the contract does declare still reach the store.
func TestAListingTakesEveryFilterTheContractDeclares(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubAlerts()
	handler := alerts(t, h, store)

	token := session(t, handler, "dev-analyst")
	asked := &alertv1.Query{
		States:     []alertv1.State{alert.Open.Wire(), alert.Resolved.Wire()},
		Severities: []detectionv1.Severity{detectionv1.Severity_SEVERITY_HIGH},
	}
	recorder := call(t, handler, http.MethodPost, control.AlertSearch, "dev-analyst", token, asked)
	if recorder.Code != http.StatusOK {
		t.Fatalf("a declared filter answered %d", recorder.Code)
	}
}

func servingAlerts(t *testing.T, h *harness) http.Handler {
	t.Helper()
	return alerts(t, h, newStubAlerts())
}

func servingIncidents(t *testing.T, h *harness) http.Handler {
	t.Helper()
	return incidents(t, h, newStubIncidents())
}

func servingAgents(t *testing.T, h *harness) http.Handler {
	t.Helper()
	return registry(t, h, newStubAgents(), &stubAdmissions{})
}
