package control_test

import (
	"net/http"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

func refusals(t *testing.T, h *harness, written string) float64 {
	t.Helper()
	permission, err := authz.ParsePermission(written)
	if err != nil {
		t.Fatal(err)
	}
	return gauged(t, h.scraped, `seagull_control_authorizations_total{action="`+permission.Action.String()+
		`",reason="no_permission",resource="`+permission.Resource.String()+`"}`)
}

// The three sequences of the 2026-11-09 integration audit, asked by the caller
// it asked them as: an administrator bound to one tenant. Each ended somebody
// else's work on the whole platform, and each is now a counted refusal.
func TestAnAdministratorOfOneTenantEndsNoSessionOfAnotherSubject(t *testing.T) {
	h := newHarness(t, nil)
	handler := routes(t, h)

	globex := open(t, h, "globex-admin")
	victim, victimToken, err := h.sessions.Open("dev-admin", authz.Fingerprint(certificate("dev-admin")), now, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	refusedWith(t, call(t, handler, http.MethodGet, control.SessionsPath+"?subject=dev-admin", "globex-admin", globex, nil),
		http.StatusForbidden, control.CodeForbidden)
	refusedWith(t, call(t, handler, http.MethodDelete, control.SessionPath, "globex-admin", globex,
		&controlv1.RevocationRequest{SessionId: victim.ID()}), http.StatusForbidden, control.CodeForbidden)

	if _, err := h.sessions.Verify(victimToken, authz.Fingerprint(certificate("dev-admin")), now); err != nil {
		t.Errorf("the session of an administrator of the platform was ended from one tenant: %v", err)
	}
	if read, ended := refusals(t, h, "sessions:read"), refusals(t, h, "sessions:delete"); read != 1 || ended != 1 {
		t.Errorf("the two refusals were counted %v and %v times", read, ended)
	}

	own := call(t, handler, http.MethodDelete, control.SessionPath, "globex-admin", globex, &controlv1.RevocationRequest{})
	if own.Code != http.StatusOK {
		t.Errorf("a caller could not end its own session: %d %s", own.Code, own.Body)
	}
}

func TestAnAdministratorOfOneTenantChangesNothingOfWhatDetectsForEveryTenant(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubRulesets()
	handler := routesWith(t, h, store)
	globex := open(t, h, "globex-admin")

	refusedWith(t, call(t, handler, http.MethodPost, control.RulesetsPath, "globex-admin", globex,
		&rulesetv1.PublishRequest{Documents: []*rulesetv1.Document{{Name: "a.yml"}}}), http.StatusForbidden, control.CodeForbidden)
	refusedWith(t, call(t, handler, http.MethodPost, "/v1/rulesets/ab01/activate", "globex-admin", globex,
		&rulesetv1.ActivationRequest{Note: "from one tenant"}), http.StatusForbidden, control.CodeForbidden)

	if store.publishedBy != "" || store.activatedBy != "" {
		t.Errorf("the ruleset store was reached: published by %q, activated by %q", store.publishedBy, store.activatedBy)
	}
	if counted := refusals(t, h, "rulesets:write"); counted != 2 {
		t.Errorf("the two refusals were counted %v times", counted)
	}

	if listed := call(t, handler, http.MethodGet, control.RulesetsPath, "globex-admin", globex, nil); listed.Code != http.StatusOK {
		t.Errorf("reading what detects answered a tenant grant %d: %s", listed.Code, listed.Body)
	}
}

func TestAnAdministratorOfThePlatformReachesNoTenantItDoesNotName(t *testing.T) {
	h := newHarness(t, nil)
	held := newStubAgents()
	held.held["db-01"] = &agentv1.Agent{AgentId: "db-01", TenantId: "globex"}
	handler := listenerRegistering(t, h, newStubRulesets(), newStubAlerts(), newStubIncidents(), held, &stubAdmissions{}, nil)
	admin := open(t, h, "dev-admin")

	refusedWith(t, call(t, handler, http.MethodPost, control.AgentsPath, "dev-admin", admin,
		&agentv1.Registration{AgentId: "db-02", TenantId: "globex", Platform: &agentv1.Platform{Os: "linux", Architecture: "amd64"}}),
		http.StatusForbidden, control.CodeForbidden)
	refusedWith(t, call(t, handler, http.MethodGet, "/v1/agents/db-01", "dev-admin", admin, nil),
		http.StatusNotFound, control.CodeUnknownAgent)

	recorder := call(t, handler, http.MethodPost, control.AgentSearch, "dev-admin", admin, &agentv1.Query{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("searching agents answered %d: %s", recorder.Code, recorder.Body)
	}
	var page agentv1.Page
	decode(t, recorder, &page)
	for _, listed := range page.GetAgents() {
		if listed.GetTenantId() != "default" {
			t.Errorf("an administrator of the platform bound to default was shown an agent of %q", listed.GetTenantId())
		}
	}
	if len(page.GetAgents()) != 1 {
		t.Errorf("%d agents were listed, and default holds one", len(page.GetAgents()))
	}
}
