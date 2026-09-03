package incident_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

func TestTriageRunsForwardsAndTheOnlyWayBackIsOutOfAnEnding(t *testing.T) {
	legal := map[incident.State][]incident.State{
		incident.Open:            {incident.Acknowledged, incident.InInvestigation, incident.Resolved, incident.FalsePositive},
		incident.Acknowledged:    {incident.InInvestigation, incident.Resolved, incident.FalsePositive},
		incident.InInvestigation: {incident.Resolved, incident.FalsePositive},
		incident.Resolved:        {incident.Open},
		incident.FalsePositive:   {incident.Open},
	}

	for _, from := range incident.States() {
		for _, to := range incident.States() {
			want := slices.Contains(legal[from], to)
			if got := incident.Legal(from, to); got != want {
				t.Errorf("%s -> %s is %v and should be %v", from, to, got, want)
			}
		}
		if slices.Contains(incident.Reachable(from), from) {
			t.Errorf("%s reaches itself", from)
		}
	}
}

func TestAStoryClosedAsFalsePositiveNeedsAReasonAndOneResolvedDoesNot(t *testing.T) {
	if !incident.Resolved.Closed() || !incident.FalsePositive.Closed() {
		t.Fatal("an ending does not report itself closed")
	}
	for _, open := range []incident.State{incident.Open, incident.Acknowledged, incident.InInvestigation} {
		if open.Closed() {
			t.Errorf("%s reports itself closed", open)
		}
	}

	if incident.Explains(incident.Open, incident.Resolved) {
		t.Error("resolving an open incident was made to need a reason")
	}
	if !incident.Explains(incident.Open, incident.FalsePositive) {
		t.Error("a story dismissed as a false positive needs no reason")
	}
	for _, ending := range []incident.State{incident.Resolved, incident.FalsePositive} {
		if !incident.Explains(ending, incident.Open) {
			t.Errorf("reopening a %s incident needs no reason", ending)
		}
	}
}

func TestEveryStateCrossesTheWireAndComesBackTheSame(t *testing.T) {
	seen := map[incidentv1.State]bool{}
	for _, named := range incident.States() {
		crossed := named.Wire()
		if crossed == incidentv1.State_STATE_UNSPECIFIED {
			t.Errorf("%s crosses the wire as unspecified", named)
			continue
		}
		if seen[crossed] {
			t.Errorf("%s shares a wire value with another state", named)
		}
		seen[crossed] = true

		back, known := incident.FromWire(crossed)
		if !known || back != named {
			t.Errorf("%s came back as %q", named, back)
		}
	}
	if _, known := incident.FromWire(incidentv1.State_STATE_UNSPECIFIED); known {
		t.Error("an unspecified state named an incident state")
	}
}

func TestARefusalNamesWhereTheIncidentCanActuallyGo(t *testing.T) {
	err := incident.Illegal(incident.InInvestigation, incident.Acknowledged)
	if err == nil {
		t.Fatal("stepping an investigation backwards was allowed")
	}
	for _, wanted := range []string{"in_investigation", "acknowledged", "resolved", "false_positive"} {
		if !strings.Contains(err.Error(), wanted) {
			t.Errorf("the refusal does not name %s: %v", wanted, err)
		}
	}
	if err := incident.Illegal(incident.Open, "archived"); err == nil ||
		!strings.Contains(err.Error(), "names no incident state") {
		t.Errorf("a state nobody declared was refused as %v", err)
	}
}
