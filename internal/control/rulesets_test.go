package control_test

import (
	"errors"
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

func TestReadingRulesetsNeedsThePermissionAndWritingNeedsMore(t *testing.T) {
	h := newHarness(t, nil)
	handler := routes(t, h)

	engineer := session(t, handler, "dev-engineer")
	analyst := session(t, handler, "dev-analyst")

	for _, subject := range []struct {
		method string
		path   string
		body   proto.Message
	}{
		{http.MethodGet, control.RulesetsPath, nil},
		{http.MethodPost, control.ValidationPath, &rulesetv1.ValidationRequest{Documents: []*rulesetv1.Document{{Name: "a.yml"}}}},
		{http.MethodPost, control.RulesetsPath, &rulesetv1.PublishRequest{Documents: []*rulesetv1.Document{{Name: "a.yml"}}}},
	} {
		if recorder := call(t, handler, subject.method, subject.path, "dev-analyst", analyst, subject.body); recorder.Code != http.StatusForbidden {
			t.Fatalf("%s %s answered an analyst %d, wanted 403", subject.method, subject.path, recorder.Code)
		}
	}

	recorder := call(t, handler, http.MethodGet, control.RulesetsPath, "dev-engineer", engineer, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("listing rulesets answered an engineer %d: %s", recorder.Code, recorder.Body)
	}
}

func TestAnInvalidRulesetIsNeverPublishedAndSaysWhy(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubRulesets()
	store.valid = false
	handler := routesWith(t, h, store)

	engineer := session(t, handler, "dev-engineer")
	recorder := call(t, handler, http.MethodPost, control.RulesetsPath, "dev-engineer", engineer,
		&rulesetv1.PublishRequest{Documents: []*rulesetv1.Document{{Name: "rules.yml", Content: []byte("broken")}}})

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("publishing a broken ruleset answered %d, wanted 422", recorder.Code)
	}

	var answer rulesetv1.PublishResponse
	decode(t, recorder, &answer)
	if answer.GetPublished() {
		t.Fatal("a ruleset that does not compile was published")
	}
	if len(answer.GetValidation().GetFaults()) == 0 {
		t.Fatal("a refusal that says nothing leaves nothing to fix")
	}
	if store.publishedBy != "" {
		t.Fatalf("the store was asked to keep a broken ruleset for %q", store.publishedBy)
	}
}

func TestARulesetWhoseCasesDoNotHoldIsNeverPublished(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubRulesets()
	store.held = false
	handler := routesWith(t, h, store)

	engineer := session(t, handler, "dev-engineer")
	recorder := call(t, handler, http.MethodPost, control.RulesetsPath, "dev-engineer", engineer,
		&rulesetv1.PublishRequest{Documents: []*rulesetv1.Document{{Name: "rules.yml"}}})

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("publishing a ruleset with an unheld case answered %d, wanted 422", recorder.Code)
	}
	if store.publishedBy != "" {
		t.Fatal("a ruleset whose own case says it is wrong was published")
	}
}

func TestPublishingThenActivatingAttributesBothToTheCaller(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubRulesets()
	handler := routesWith(t, h, store)

	engineer := session(t, handler, "dev-engineer")
	recorder := call(t, handler, http.MethodPost, control.RulesetsPath, "dev-engineer", engineer,
		&rulesetv1.PublishRequest{Documents: []*rulesetv1.Document{{Name: "rules.yml"}}, Note: "first"})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("publishing answered %d: %s", recorder.Code, recorder.Body)
	}

	var published rulesetv1.PublishResponse
	decode(t, recorder, &published)
	if !published.GetPublished() || published.GetRulesetId() == "" {
		t.Fatalf("a good ruleset was not published: %v", &published)
	}
	if store.publishedBy != "dev-engineer" {
		t.Fatalf("the ruleset was attributed to %q", store.publishedBy)
	}

	recorder = call(t, handler, http.MethodPost, "/v1/rulesets/"+published.GetRulesetId()+"/activate",
		"dev-engineer", engineer, &rulesetv1.ActivationRequest{Note: "rolling out"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("activating answered %d: %s", recorder.Code, recorder.Body)
	}

	var activated rulesetv1.ActivationResponse
	decode(t, recorder, &activated)
	if activated.GetActive().GetActivatedBy() != "dev-engineer" {
		t.Fatalf("the activation was attributed to %q", activated.GetActive().GetActivatedBy())
	}
	if activated.GetReplaced() != "ab01" {
		t.Fatalf("the activation replaced %q, wanted ab01", activated.GetReplaced())
	}
}

func TestActivatingARulesetNobodyPublishedIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	handler := routesWith(t, h, newStubRulesets())

	engineer := session(t, handler, "dev-engineer")
	recorder := call(t, handler, http.MethodPost, "/v1/rulesets/beef/activate", "dev-engineer", engineer, &rulesetv1.ActivationRequest{})
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("activating an unpublished ruleset answered %d, wanted 404", recorder.Code)
	}

	var refusal controlv1.Refusal
	decode(t, recorder, &refusal)
	if refusal.GetCode() != control.CodeUnknownRuleset {
		t.Fatalf("the refusal carried %q", refusal.GetCode())
	}
}

func TestPublishingNothingIsRefusedBeforeAnythingIsCompiled(t *testing.T) {
	h := newHarness(t, nil)
	store := newStubRulesets()
	store.unreached = errors.New("the backbone must not be reached for an empty publish")
	handler := routesWith(t, h, store)

	engineer := session(t, handler, "dev-engineer")
	recorder := call(t, handler, http.MethodPost, control.RulesetsPath, "dev-engineer", engineer, &rulesetv1.PublishRequest{})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("publishing no documents answered %d, wanted 400", recorder.Code)
	}
}
