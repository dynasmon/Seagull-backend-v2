package control_test

import (
	"net/http"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
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

func TestAnAdministratorOfOneTenantPublishesNothingEveryAgentMayInstall(t *testing.T) {
	h := newHarness(t, nil)
	published := publishUpdates(t, h)
	handler := updateListener(t, h, published.held, published.store, published.anchor)
	globex := open(t, h, "globex-admin")
	roots, packages, catalogs := len(published.store.roots), len(published.store.packages), len(published.store.catalogs)

	refusedWith(t, call(t, handler, http.MethodPost, control.UpdateRootsPath, "globex-admin", globex,
		&updatev1.RootPublication{Root: updateRoot(t, 3, published.owner, published.publisher, published.owner)}),
		http.StatusForbidden, control.CodeForbidden)
	refusedWith(t, upload(t, handler, "globex-admin", globex, []byte("any bytes at all")), http.StatusForbidden, control.CodeForbidden)
	refusedWith(t, call(t, handler, http.MethodPost, control.UpdateCatalogsPath, "globex-admin", globex,
		&updatev1.CatalogPublication{Catalog: updateCatalog(t, 2, published.publisher)}), http.StatusForbidden, control.CodeForbidden)

	if len(published.store.roots) != roots || len(published.store.packages) != packages || len(published.store.catalogs) != catalogs {
		t.Errorf("the update store was reached: %d roots, %d packages, %d catalogs",
			len(published.store.roots), len(published.store.packages), len(published.store.catalogs))
	}
	if counted := refusals(t, h, "releases:write"); counted != 3 {
		t.Errorf("the three refusals were counted %v times", counted)
	}
}

// Writing agents stays a tenant's: who registers a machine into a tenant and
// says which release it runs is not thereby who decides what a release is.
func TestAssigningAReleaseNeedsToWriteAgentsOfTheTenantAndNothingOfThePlatform(t *testing.T) {
	h := newHarness(t, nil)
	published := publishUpdates(t, h)
	published.held.held["db-01"] = &agentv1.Agent{AgentId: "db-01", TenantId: "globex"}
	handler := updateListener(t, h, published.held, published.store, published.anchor)

	assigned := call(t, handler, http.MethodPost, control.UpdateAssignmentsPath, "globex-admin", open(t, h, "globex-admin"),
		&updatev1.Assignment{TenantId: "globex", AgentIds: []string{"db-01"}, Version: "v0.2.0"})
	if assigned.Code != http.StatusOK {
		t.Fatalf("an administrator of globex assigning a release to its agent answered %d: %s", assigned.Code, assigned.Body)
	}
	refusedWith(t, call(t, handler, http.MethodPost, control.UpdateAssignmentsPath, "globex-admin", open(t, h, "globex-admin"),
		&updatev1.Assignment{TenantId: "default", AgentIds: []string{"web-01"}, Version: "v0.2.0"}), http.StatusForbidden, control.CodeForbidden)
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

// What a caller is shown says what its grant reaches and names every permission
// it holds, the publication of a release among them: a client that draws its
// controls from the grant draws the same line the server decides by.
func TestASessionTellsACallerWhatItsGrantReaches(t *testing.T) {
	h := newHarness(t, nil)
	handler := routes(t, h)

	for subject, want := range map[string]struct {
		scope    controlv1.Scope
		releases bool
	}{
		"dev-admin":    {controlv1.Scope_SCOPE_PLATFORM, true},
		"globex-admin": {controlv1.Scope_SCOPE_TENANT, false},
	} {
		recorder := call(t, handler, http.MethodPost, control.SessionPath, subject, "", &controlv1.SessionRequest{})
		if recorder.Code != http.StatusCreated {
			t.Fatalf("opening a session for %s answered %d: %s", subject, recorder.Code, recorder.Body)
		}
		var answer controlv1.SessionResponse
		decode(t, recorder, &answer)

		grant := answer.GetSession().GetGrant()
		if grant.GetScope() != want.scope {
			t.Errorf("%s is told its grant reaches %s, want %s", subject, grant.GetScope(), want.scope)
		}
		told := false
		for _, permission := range grant.GetPermissions() {
			told = told || (permission.GetResource() == controlv1.Resource_RESOURCE_RELEASES &&
				permission.GetAction() == controlv1.Action_ACTION_WRITE)
		}
		if told != want.releases {
			t.Errorf("%s is told it publishes releases: %v, want %v", subject, told, want.releases)
		}
	}
}
