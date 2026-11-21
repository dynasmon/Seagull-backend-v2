package control_test

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

type stubFindings struct {
	*stubLiveness
	open      map[string][]*agentv1.Finding
	page      *agentv1.FindingPage
	searched  []*agentv1.FindingQuery
	scopes    [][]string
	unreached error
	cursor    bool
}

func (s *stubFindings) Open(_ context.Context, agents, tenants []string) (map[string][]*agentv1.Finding, error) {
	if s.unreached != nil {
		return nil, s.unreached
	}
	answered := map[string][]*agentv1.Finding{}
	for _, agentID := range agents {
		if held, known := s.open[agentID]; known && len(tenants) > 0 {
			answered[agentID] = held
		}
	}
	return answered, nil
}

func (s *stubFindings) Search(_ context.Context, asked *agentv1.FindingQuery, tenants []string) (*agentv1.FindingPage, error) {
	s.searched = append(s.searched, proto.Clone(asked).(*agentv1.FindingQuery))
	s.scopes = append(s.scopes, slices.Clone(tenants))
	switch {
	case s.cursor:
		return nil, agentfinding.ErrCursor
	case s.unreached != nil:
		return nil, s.unreached
	}
	return s.page, nil
}

func openSilence(agentID string) *agentv1.Finding {
	at := time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC)
	return &agentv1.Finding{
		SchemaVersion:  agentfinding.SchemaVersion,
		FindingId:      agentfinding.ID("default", agentID, agentv1.Finding_KIND_SILENCE, "boot", "41"),
		TenantId:       "default",
		AgentId:        agentID,
		Kind:           agentv1.Finding_KIND_SILENCE,
		State:          agentv1.Finding_STATE_OPEN,
		OpenedAt:       timestamppb.New(at),
		LastObservedAt: timestamppb.New(at),
		Observations:   1,
		DecidedAt:      timestamppb.New(at.Add(time.Second)),
	}
}

func TestOnlyReadingOneAgentCarriesItsOpenFindings(t *testing.T) {
	h := newHarness(t, nil)
	silent := openSilence("web-01")
	handler := listenerReading(t, h, newStubAgents(), &stubAdmissions{}, &stubFindings{
		stubLiveness: &stubLiveness{},
		open:         map[string][]*agentv1.Finding{"web-01": {silent}},
	})
	operator := session(t, handler, "dev-admin")

	response := call(t, handler, http.MethodPost, "/v1/agents/search", "dev-admin", operator, &agentv1.Query{})
	var page agentv1.Page
	if err := proto.Unmarshal(response.Body.Bytes(), &page); err != nil || response.Code != http.StatusOK {
		t.Fatalf("searching agents answered %d: %v", response.Code, err)
	}
	for _, listed := range page.GetAgents() {
		if len(listed.GetFindings()) > 0 {
			t.Errorf("a page carried the findings of %s", listed.GetAgentId())
		}
	}

	response = call(t, handler, http.MethodGet, "/v1/agents/web-01", "dev-admin", operator, nil)
	var one agentv1.Agent
	if err := proto.Unmarshal(response.Body.Bytes(), &one); err != nil || response.Code != http.StatusOK {
		t.Fatalf("reading an agent answered %d: %v", response.Code, err)
	}
	if len(one.GetFindings()) != 1 || !proto.Equal(one.GetFindings()[0], silent) {
		t.Errorf("reading one agent carried %v, want its open silence", one.GetFindings())
	}
}

func TestAFindingStoreThatDoesNotAnswerLeavesTheAgentReadableWithoutFindings(t *testing.T) {
	h := newHarness(t, nil)
	handler := listenerReading(t, h, newStubAgents(), &stubAdmissions{}, &stubFindings{
		stubLiveness: &stubLiveness{},
		open:         map[string][]*agentv1.Finding{"web-01": {openSilence("web-01")}},
		unreached:    errors.New("the finding store is unreachable"),
	})

	response := call(t, handler, http.MethodGet, "/v1/agents/web-01", "dev-admin", session(t, handler, "dev-admin"), nil)
	var one agentv1.Agent
	if err := proto.Unmarshal(response.Body.Bytes(), &one); err != nil || response.Code != http.StatusOK {
		t.Fatalf("an unreachable finding store made an agent unreadable: %d %v", response.Code, err)
	}
	if len(one.GetFindings()) != 0 {
		t.Fatal("findings nobody could read were answered anyway")
	}
}

func TestFindingsAreSearchedWithinTheTenantsTheCallerHoldsAndNeedTheAgentsToBeReadable(t *testing.T) {
	h := newHarness(t, nil)
	found := &stubFindings{stubLiveness: &stubLiveness{}, page: &agentv1.FindingPage{Findings: []*agentv1.Finding{openSilence("web-01")}}}
	handler := listenerReading(t, h, newStubAgents(), &stubAdmissions{}, found)

	asked := &agentv1.FindingQuery{
		Kinds:  []agentv1.Finding_Kind{agentv1.Finding_KIND_SILENCE},
		States: []agentv1.Finding_State{agentv1.Finding_STATE_OPEN},
		Limit:  10,
	}
	response := call(t, handler, http.MethodPost, control.AgentFindingSearch, "dev-analyst", session(t, handler, "dev-analyst"), asked)
	var page agentv1.FindingPage
	if err := proto.Unmarshal(response.Body.Bytes(), &page); err != nil || response.Code != http.StatusOK {
		t.Fatalf("an analyst searching findings was answered %d: %v", response.Code, err)
	}
	if len(page.GetFindings()) != 1 || len(found.searched) != 1 || !proto.Equal(found.searched[0], asked) {
		t.Fatalf("the search reached the store as %v and answered %v", found.searched, page.GetFindings())
	}
	if !slices.Equal(found.scopes[0], []string{"default"}) {
		t.Errorf("the search was scoped to %v, and the analyst holds default", found.scopes[0])
	}

	refused := call(t, handler, http.MethodPost, control.AgentFindingSearch, "dev-engineer", session(t, handler, "dev-engineer"), asked)
	if refused.Code != http.StatusForbidden || len(found.searched) != 1 {
		t.Errorf("an engineer searching findings was answered %d and reached the store %d times", refused.Code, len(found.searched))
	}
}

func TestAFindingSearchAskingForWhatTheContractDoesNotDeclareIsRefusedBeforeTheStore(t *testing.T) {
	h := newHarness(t, nil)
	found := &stubFindings{stubLiveness: &stubLiveness{}, page: &agentv1.FindingPage{}}
	handler := listenerReading(t, h, newStubAgents(), &stubAdmissions{}, found)
	operator := session(t, handler, "dev-admin")

	at := time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC)
	for name, asked := range map[string]*agentv1.FindingQuery{
		"an undeclared kind":          {Kinds: []agentv1.Finding_Kind{agentv1.Finding_Kind(99)}},
		"an unspecified kind":         {Kinds: []agentv1.Finding_Kind{agentv1.Finding_KIND_UNSPECIFIED}},
		"an undeclared state":         {States: []agentv1.Finding_State{agentv1.Finding_State(7)}},
		"a range ending at its start": {Range: &huntv1.TimeRange{Start: timestamppb.New(at), End: timestamppb.New(at)}},
	} {
		if response := call(t, handler, http.MethodPost, control.AgentFindingSearch, "dev-admin", operator, asked); response.Code != http.StatusUnprocessableEntity {
			t.Errorf("a search with %s was answered %d", name, response.Code)
		}
	}
	if len(found.searched) != 0 {
		t.Errorf("%d refused searches reached the store", len(found.searched))
	}
}

func TestAFindingSearchTellsAnInventedCursorFromAStoreThatDoesNotAnswer(t *testing.T) {
	h := newHarness(t, nil)
	invented := &stubFindings{stubLiveness: &stubLiveness{}, cursor: true}
	handler := listenerReading(t, h, newStubAgents(), &stubAdmissions{}, invented)
	if response := call(t, handler, http.MethodPost, control.AgentFindingSearch, "dev-admin", session(t, handler, "dev-admin"),
		&agentv1.FindingQuery{Cursor: "not-a-cursor"}); response.Code != http.StatusBadRequest {
		t.Errorf("an invented cursor was answered %d", response.Code)
	}

	unreached := &stubFindings{stubLiveness: &stubLiveness{}, unreached: errors.New("the finding store is unreachable")}
	handler = listenerReading(t, h, newStubAgents(), &stubAdmissions{}, unreached)
	if response := call(t, handler, http.MethodPost, control.AgentFindingSearch, "dev-admin", session(t, handler, "dev-admin"),
		&agentv1.FindingQuery{}); response.Code != http.StatusServiceUnavailable {
		t.Errorf("a search the store did not answer was answered %d", response.Code)
	}
}

type stubOpenFindings struct {
	open   map[string]int
	broken error
}

func (s *stubOpenFindings) CountOpen(context.Context) (map[string]int, error) {
	return maps.Clone(s.open), s.broken
}

func TestTheFleetCountCarriesTheOpenFindingsByKindAndAFailedCountPublishesNeither(t *testing.T) {
	clock := time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC)
	registry := &stubAdmitted{agents: map[string]string{"web-01": "default"}}
	reports := &stubHeard{held: map[string]heardOf{
		"web-01": {"default", agentstatus.Heard{Received: clock.Add(-30 * time.Second), Interval: time.Minute}},
	}}
	open := &stubOpenFindings{open: map[string]int{"silence": 2, "shared_identity": 1}}
	exported := metrics.New("control-api-fleet-findings")
	reader, err := control.NewFleetReader(control.FleetReaderOptions{
		Registry: registry, Reports: reports, Findings: open, Metrics: control.NewMetrics(exported),
		Logger: slog.New(slog.DiscardHandler), Every: 30 * time.Second, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}

	reader.Sweep(context.Background())
	want := map[string]float64{"silence": 2, "copied_installation": 0, "shared_identity": 1, "replaced_certificate": 0}
	for kind, expected := range want {
		if got := gauged(t, exported, `seagull_control_fleet_findings_open{kind="`+kind+`"}`); got != expected {
			t.Errorf("%v open %s findings are counted, want %v", got, kind, expected)
		}
	}

	open.open, open.broken = map[string]int{"silence": 9}, errors.New("the finding store is unreachable")
	reports.held["web-01"] = heardOf{"default", agentstatus.Heard{Received: clock.Add(-time.Hour), Interval: time.Minute}}
	reader.Sweep(context.Background())
	if got := gauged(t, exported, `seagull_control_fleet_findings_open{kind="silence"}`); got != 2 {
		t.Errorf("a count that failed moved the open silences to %v", got)
	}
	if got := gauged(t, exported, `seagull_control_fleet_agents{liveness="active"}`); got != 1 {
		t.Errorf("a reading whose findings failed still published a liveness count: %v active", got)
	}
	if unreadable := gauged(t, exported, `seagull_control_fleet_readings_total{outcome="unreadable"}`); unreadable != 1 {
		t.Errorf("%v readings are counted unreadable", unreadable)
	}
}
