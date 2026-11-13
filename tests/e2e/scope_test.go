package e2e_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/policyfile"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// The binding the 2026-11-09 integration audit wrote: the role that administers
// the platform, bound to one tenant. It is refused where it is read, so no
// process starts deciding by it.
func TestThePolicyTheIntegrationAuditWroteIsNotLoaded(t *testing.T) {
	audited := strings.Replace(controlPolicy,
		"    roles: [administrator]\n    scope: platform\n    tenants: [default]",
		"    roles: [administrator]\n    scope: tenant\n    tenants: [another-tenant]", 1)
	if audited == controlPolicy {
		t.Fatal("the administrator's binding was not found to rewrite")
	}

	_, err := policyfile.Read("policy.yml", []byte(audited))
	if err == nil {
		t.Fatal("an administrator of the platform bound to one tenant was loaded")
	}
	if !errors.Is(err, authz.ErrPlatformPermission) || !strings.Contains(err.Error(), "e2e-admin") {
		t.Errorf("the refusal %q does not name the binding and why", err)
	}
}

// The audit's three sequences over real mutual TLS, asked by an administrator
// of one tenant: another subject's sessions, what detects for every tenant, and
// what every agent may install.
func TestAnAdministratorOfOneTenantIsRefusedWhatEveryTenantSharesOverRealTLS(t *testing.T) {
	plane := startControlAPI(t, nil)
	platform := plane.caller(t, "e2e-admin")
	tenant := plane.caller(t, "e2e-tenant-admin")
	held := plane.open(t, platform)
	token := plane.open(t, tenant).GetToken()

	forbidden := func(what string, response *http.Response, body []byte) {
		t.Helper()
		if response.StatusCode != http.StatusForbidden || refusalCode(t, body) != control.CodeForbidden {
			t.Errorf("%s was answered %d %q: %s", what, response.StatusCode, refusalCode(t, body), body)
		}
	}

	response, body := plane.send(t, tenant, http.MethodGet, control.SessionsPath+"?subject=e2e-admin", token, nil)
	forbidden("listing the sessions of an administrator of the platform", response, body)
	response, body = plane.send(t, tenant, http.MethodDelete, control.SessionPath, token,
		&controlv1.RevocationRequest{SessionId: held.GetSession().GetId()})
	forbidden("ending the session of an administrator of the platform", response, body)
	if response, body := plane.send(t, platform, http.MethodGet, control.SessionPath, held.GetToken(), nil); response.StatusCode != http.StatusOK {
		t.Errorf("the session a tenant grant was refused to end answers %d: %s", response.StatusCode, body)
	}

	response, body = plane.send(t, tenant, http.MethodPost, control.RulesetsPath, token,
		&rulesetv1.PublishRequest{Documents: []*rulesetv1.Document{{Name: "a.yml"}}})
	forbidden("publishing a ruleset", response, body)
	response, body = plane.send(t, tenant, http.MethodPost, "/v1/rulesets/e2e01/activate", token, &rulesetv1.ActivationRequest{})
	forbidden("activating a ruleset", response, body)
	if response, body := plane.send(t, tenant, http.MethodGet, control.RulesetsPath, token, nil); response.StatusCode != http.StatusOK {
		t.Errorf("reading the rulesets answered a tenant grant %d: %s", response.StatusCode, body)
	}

	response, body = plane.send(t, tenant, http.MethodPost, control.UpdateRootsPath, token,
		&updatev1.RootPublication{Root: updateRootSigned(t, 2, plane.updateKey, plane.updateKey)})
	forbidden("publishing an update root", response, body)
	given := plane.give(t, tenant, token, []byte("any bytes at all"))
	if given.StatusCode != http.StatusForbidden {
		t.Errorf("giving a package was answered %d", given.StatusCode)
	}
	response, body = plane.send(t, tenant, http.MethodPost, control.UpdateCatalogsPath, token,
		&updatev1.CatalogPublication{Catalog: releaseCatalog(t, 1, plane.updateKey)})
	forbidden("publishing a catalog", response, body)

	ended, body := plane.send(t, tenant, http.MethodDelete, control.SessionPath, token, &controlv1.RevocationRequest{})
	if ended.StatusCode != http.StatusOK {
		t.Errorf("a caller could not end its own session: %d %s", ended.StatusCode, body)
	}
}
