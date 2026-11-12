//go:build integration

package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// A grant of the platform may list no tenant, so a store is asked with an empty
// scope by a caller the policy does bind. It answers nothing: the absence of a
// tenant is never every tenant, whichever way the list arrives empty.
func TestACallerNamingNoTenantReachesNoRecordOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, at := isolated(t), time.Now().UTC()
	agentID := registeredIn(t, ctx, store, tenant)
	raised := raisedFrom(t, tenant, tenant+"-alert", detectionv1.Severity_SEVERITY_HIGH, at)
	recorded(t, store, mustConsider(t, raised))
	told := openedFrom(t, tenant, tenant+"-story", at, 0)
	opened(t, store.Incidents(), told)
	if _, err := store.AgentPolicies().Publish(ctx, newPolicySigner(t).accepted(t, tenant, 1, agentID)); err != nil {
		t.Fatalf("publish a policy: %v", err)
	}

	for name, nobody := range map[string][]string{"no list": nil, "an empty list": {}} {
		if _, err := store.Agents().Agent(ctx, agentID, nobody); !errors.Is(err, agent.ErrUnknown) {
			t.Errorf("%s read an agent: %v", name, err)
		}
		if _, err := store.Agents().Move(ctx, agentID, nobody, agent.Move{
			To: agent.Decommissioned, Actor: "nobody", At: at,
		}); !errors.Is(err, agent.ErrUnknown) {
			t.Errorf("%s retired an agent: %v", name, err)
		}
		if page, err := store.Agents().Page(ctx, &agentv1.Query{}, nobody); err != nil || len(page.GetAgents()) != 0 {
			t.Errorf("%s listed %d agents: %v", name, len(page.GetAgents()), err)
		}

		if _, err := store.Alert(ctx, raised.GetAlertId(), nobody); !errors.Is(err, alert.ErrUnknownAlert) {
			t.Errorf("%s read an alert: %v", name, err)
		}
		if _, err := store.Move(ctx, raised.GetAlertId(), nobody, alert.Move{
			To: alert.Acknowledged, Actor: "nobody", At: at,
		}); !errors.Is(err, alert.ErrUnknownAlert) {
			t.Errorf("%s moved an alert: %v", name, err)
		}
		if page, err := store.Page(ctx, &alertv1.Query{}, nobody); err != nil || len(page.GetAlerts()) != 0 {
			t.Errorf("%s listed %d alerts: %v", name, len(page.GetAlerts()), err)
		}

		if _, err := store.Incidents().Incident(ctx, told.GetIncidentId(), nobody); !errors.Is(err, incident.ErrUnknownIncident) {
			t.Errorf("%s read an incident: %v", name, err)
		}
		if page, err := store.Incidents().Page(ctx, &incidentv1.Query{}, nobody); err != nil || len(page.GetIncidents()) != 0 {
			t.Errorf("%s listed %d incidents: %v", name, len(page.GetIncidents()), err)
		}

		if _, err := store.AgentPolicies().Policy(ctx, tenant, 1, nobody); !errors.Is(err, agentpolicy.ErrUnknown) {
			t.Errorf("%s read a policy: %v", name, err)
		}
		if page, err := store.AgentPolicies().Page(ctx, &policyv1.Query{TenantIds: []string{tenant}}, nobody); err != nil || len(page.GetPolicies()) != 0 {
			t.Errorf("%s listed %d policies: %v", name, len(page.GetPolicies()), err)
		}
		if page, err := store.AgentRollouts().Page(ctx, &updatev1.RolloutQuery{}, nobody); err != nil || len(page.GetRollouts()) != 0 {
			t.Errorf("%s listed %d rollouts: %v", name, len(page.GetRollouts()), err)
		}
	}
}
