package e2e_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// What the read plane's stores were asked, by any of its listings.
type holding struct {
	mu     sync.Mutex
	scopes []hunt.Scope
}

func (h *holding) record(scope hunt.Scope) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scopes = append(h.scopes, scope)
}

func (h *holding) asked() []hunt.Scope {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.scopes)
}

func (h *holding) Assets(_ context.Context, asked hunt.AssetQuestion) (*inventoryv1.AssetPage, []string, error) {
	h.record(asked.Scope())
	return &inventoryv1.AssetPage{Assets: []*inventoryv1.Asset{{TenantId: "acme", AgentId: "web-01"}}}, []string{"acme", "web-01"}, nil
}

func (h *holding) Items(_ context.Context, asked hunt.ItemQuestion) (*inventoryv1.ItemPage, []string, error) {
	h.record(asked.Scope())
	return &inventoryv1.ItemPage{}, nil, nil
}

func (h *holding) Findings(_ context.Context, asked hunt.FindingQuestion) (*vulnerabilityv1.FindingPage, []string, error) {
	h.record(asked.Scope())
	return &vulnerabilityv1.FindingPage{}, nil, nil
}

func (h *holding) History(_ context.Context, asked hunt.HistoryQuestion) (*vulnerabilityv1.FindingPage, []string, error) {
	h.record(asked.Scope())
	return &vulnerabilityv1.FindingPage{}, nil, nil
}

func (h *holding) Assessments(_ context.Context, asked hunt.AssessmentQuestion) (*vulnerabilityv1.AssessmentPage, []string, error) {
	h.record(asked.Scope())
	return &vulnerabilityv1.AssessmentPage{}, nil, nil
}

func (h *holding) Advisories(_ context.Context, asked hunt.AdvisoryQuestion) (*vulnerabilityv1.AdvisoryPage, []string, error) {
	h.record(asked.Scope())
	return &vulnerabilityv1.AdvisoryPage{}, nil, nil
}

func (q *queryPlane) list(t *testing.T, client *http.Client, method, path string, question proto.Message) (*http.Response, []byte) {
	t.Helper()

	encoded, err := proto.Marshal(question)
	if err != nil {
		t.Fatalf("encode the question: %v", err)
	}
	request, err := http.NewRequest(method, "https://"+q.address+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	request.Header.Set("Content-Type", hunt.ContentType)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("ask the query plane: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	return response, body
}

var listings = map[string]proto.Message{
	hunt.AssetsPath:         &inventoryv1.AssetQuery{},
	hunt.ItemsPath:          &inventoryv1.ItemQuery{AgentId: "web-01", Kind: inventoryv1.Kind_KIND_PACKAGE},
	hunt.FindingsPath:       &vulnerabilityv1.FindingQuery{},
	hunt.FindingHistoryPath: &vulnerabilityv1.FindingHistoryQuery{AgentId: "web-01", ItemId: "a232cc002c99c96b", VulnerabilityId: "CVE-2024-6387"},
	hunt.AssessmentsPath:    &vulnerabilityv1.AssessmentQuery{},
	hunt.AdvisoriesPath: &vulnerabilityv1.AdvisoryQuery{Question: &vulnerabilityv1.AdvisoryQuery_Package{
		Package: &vulnerabilityv1.AdvisedPackage{Ecosystem: "Debian:12", Name: "openssh"},
	}},
}

// Every listing is a route of the query listener, asked with a POST and the
// question in its body, and answered within the tenants the policy grants.
func TestEveryListingIsServedOnTheQueryListenerWithinTheTenantsThePolicyGrants(t *testing.T) {
	plane := startQueryAPI(t, &answering{})
	keeper := plane.caller(t, "keeper-01", []string{"globex"})

	for path, question := range listings {
		response, body := plane.list(t, keeper, http.MethodPost, path, question)
		if response.StatusCode != http.StatusOK {
			t.Errorf("%s was answered %d: %s", path, response.StatusCode, body)
		}
		if response, _ := plane.list(t, keeper, http.MethodGet, path, question); response.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("a GET of %s was answered %d", path, response.StatusCode)
		}
	}
	for _, scope := range plane.held.asked() {
		if tenants := scope.Tenants(); !slices.Equal(tenants, []string{"acme"}) {
			t.Errorf("a listing read %v, and the policy grants acme alone", tenants)
		}
	}
	if asked := len(plane.held.asked()); asked != len(listings) {
		t.Errorf("the store was asked %d times for %d listings", asked, len(listings))
	}
}

// A subject the policy lets hunt and nothing else reads no inventory and no
// finding, whatever its certificate names.
func TestACallerThePolicyDoesNotLetReadWhatAssetsHaveIsRefusedOverTheListener(t *testing.T) {
	plane := startQueryAPI(t, &answering{})
	analyst := plane.caller(t, "analyst-01", []string{"acme"})

	for path, question := range listings {
		response, body := plane.list(t, analyst, http.MethodPost, path, question)
		var refusal huntv1.Refusal
		if err := proto.Unmarshal(body, &refusal); err != nil || response.StatusCode != http.StatusForbidden || refusal.GetCode() != hunt.CodeForbidden {
			t.Errorf("%s asked by a hunter alone was answered %d %q (%v)", path, response.StatusCode, refusal.GetCode(), err)
		}
	}
	if asked := plane.held.asked(); len(asked) != 0 {
		t.Errorf("a caller without the permission reached the store %d times", len(asked))
	}
}
