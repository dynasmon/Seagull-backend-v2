package control_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

func describedTo(t *testing.T, handler http.Handler, subject string, held ...string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, control.DescriptorPath, nil)
	if subject != "" {
		r.TLS = request(t, subject, "").TLS
	}
	for _, tag := range held {
		r.Header.Add("If-None-Match", tag)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

func offered(t *testing.T, handler http.Handler) map[string]*platformv1.Capability {
	t.Helper()
	recorder := describedTo(t, handler, "web-01")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != control.ContentType {
		t.Fatalf("the agent listener described itself with %d as %q: %s", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body)
	}
	var described platformv1.Descriptor
	if err := proto.Unmarshal(recorder.Body.Bytes(), &described); err != nil {
		t.Fatal(err)
	}
	if len(described.GetStreams()) != 0 || described.GetMaxBodyBytes() != 0 || described.GetServerTime() == nil {
		t.Fatalf("the agent listener describes streams %v, a body of %d and the time %v, and it admits no stream",
			described.GetStreams(), described.GetMaxBodyBytes(), described.GetServerTime())
	}
	held := map[string]*platformv1.Capability{}
	for _, capability := range described.GetCapabilities() {
		if held[capability.GetName()] != nil {
			t.Fatalf("the agent listener offers %s twice", capability.GetName())
		}
		held[capability.GetName()] = capability
	}
	return held
}

// Each route an offer names is one the listener routes, with that method: a
// path it routes answers another method 405, and one it does not route 404.
func routed(t *testing.T, handler http.Handler, capability *platformv1.Capability) {
	t.Helper()
	method, path, found := strings.Cut(capability.GetRoute(), " ")
	if !found {
		t.Fatalf("%s is offered at %q, which is not a method and a path", capability.GetName(), capability.GetRoute())
	}
	other := http.MethodDelete
	if method == http.MethodDelete {
		other = http.MethodPut
	}
	if recorder := call(t, handler, other, path, "web-01", "", nil); recorder.Code != http.StatusMethodNotAllowed ||
		!strings.Contains(recorder.Header().Get("Allow"), method) {
		t.Fatalf("%s is offered at %s, and the listener answers %s %s with %d allowing %q", capability.GetName(), capability.GetRoute(),
			other, path, recorder.Code, recorder.Header().Get("Allow"))
	}
}

func TestTheAgentListenerOffersWhatItServesAndNothingElse(t *testing.T) {
	held := newStubAgents()
	plain := renewals(t, held, nil)
	capabilities := offered(t, plain)
	if len(capabilities) != 2 || capabilities[protocol.CapabilityRenewal] == nil || capabilities[protocol.CapabilityPolicy] == nil {
		t.Fatalf("a plane built without updates offers %v", capabilities)
	}
	if renewal := capabilities[protocol.CapabilityRenewal]; renewal.GetRoute() != http.MethodPost+" "+control.RenewalPath || renewal.GetSupportedSchema() != nil {
		t.Errorf("renewal is offered as %v", renewal)
	}
	if policy := capabilities[protocol.CapabilityPolicy]; policy.GetRoute() != http.MethodGet+" "+control.PolicyPath ||
		policy.GetSupportedSchema().GetMinimum() != agentpolicy.SchemaVersion || policy.GetSupportedSchema().GetMaximum() != agentpolicy.SchemaVersion {
		t.Errorf("policy is offered as %v", policy)
	}
	for _, capability := range capabilities {
		routed(t, plain, capability)
	}

	updating := updateFacing(t, held, newStubUpdates(held), func() (*agentupdate.Root, error) { return nil, errors.New("not asked") }, nil)
	capabilities = offered(t, updating)
	update := capabilities[protocol.CapabilityUpdate]
	if len(capabilities) != 3 || update == nil || update.GetRoute() != http.MethodGet+" "+control.UpdatePath ||
		update.GetSupportedSchema().GetMinimum() != agentupdate.SchemaVersion || update.GetSupportedSchema().GetMaximum() != agentupdate.SchemaVersion {
		t.Fatalf("a plane that hands out updates offers %v", capabilities)
	}
	for _, capability := range capabilities {
		routed(t, updating, capability)
	}
}

func TestTheAgentListenerDescribesItselfOnlyToAnAgentItCanName(t *testing.T) {
	handler := renewals(t, newStubAgents(), nil)
	if recorder := describedTo(t, handler, ""); recorder.Code != http.StatusUnauthorized || recorder.Header().Get("ETag") != "" {
		t.Fatalf("a request without a certificate was answered %d with the tag %q", recorder.Code, recorder.Header().Get("ETag"))
	}

	first := describedTo(t, handler, "web-01")
	tag := first.Header().Get("ETag")
	if first.Code != http.StatusOK || tag == "" {
		t.Fatalf("the descriptor was answered %d with the tag %q", first.Code, tag)
	}
	if again := describedTo(t, handler, "web-02", tag); again.Code != http.StatusNotModified || again.Body.Len() != 0 || again.Header().Get("ETag") != tag {
		t.Fatalf("asked again with its tag, the descriptor was answered %d with %d bytes", again.Code, again.Body.Len())
	}

	held := newStubAgents()
	updating := updateFacing(t, held, newStubUpdates(held), func() (*agentupdate.Root, error) { return nil, errors.New("not asked") }, nil)
	if other := describedTo(t, updating, "web-01").Header().Get("ETag"); other == tag {
		t.Fatal("a plane that hands out updates tags its descriptor as one that does not")
	}
}
