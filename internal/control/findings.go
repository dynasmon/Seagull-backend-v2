package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const (
	AgentFindingSearch = "/v1/agents/findings/search"

	CodeFindingsUnavailable = "agent_findings_unavailable"
)

// What the platform found about the agents of the tenants a caller holds, asked
// of where the agent finding writer keeps every finding, with the bounds the
// other observed reads have: the agents and the tenants of one read.
type Findings interface {
	Open(ctx context.Context, agents, tenants []string) (map[string][]*agentv1.Finding, error)
	Search(ctx context.Context, asked *agentv1.FindingQuery, tenants []string) (*agentv1.FindingPage, error)
}

func (s *Server) searchFindings() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		if s.findings == nil {
			Refuse(w, http.StatusServiceUnavailable, CodeFindingsUnavailable, "this control plane reads no agent findings")
			return
		}

		var asked agentv1.FindingQuery
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}
		if err := findingFilters(&asked); err != nil {
			Refuse(w, http.StatusUnprocessableEntity, CodeUnknownFilter, err.Error())
			return
		}

		page, err := s.findings.Search(r.Context(), &asked, caller.Grant.Tenants())
		switch {
		case errors.Is(err, agentfinding.ErrCursor):
			Refuse(w, http.StatusBadRequest, CodeBadCursor, err.Error())
		case err != nil:
			s.unavailable(w, CodeFindingsUnavailable, err)
		default:
			respond(w, http.StatusOK, page)
		}
	})
}

func findingFilters(asked *agentv1.FindingQuery) error {
	for _, kind := range asked.GetKinds() {
		if kind == agentv1.Finding_KIND_UNSPECIFIED || !declares(int32(kind), agentv1.Finding_Kind_name) {
			return fmt.Errorf("kinds names %s, which is not a kind of finding", kind)
		}
	}
	for _, state := range asked.GetStates() {
		if state == agentv1.Finding_STATE_UNSPECIFIED || !declares(int32(state), agentv1.Finding_State_name) {
			return fmt.Errorf("states names %s, which is not where a finding stands", state)
		}
	}
	if start, end := asked.GetRange().GetStart(), asked.GetRange().GetEnd(); start != nil && end != nil && !start.AsTime().Before(end.AsTime()) {
		return errors.New("range ends before it starts")
	}
	return nil
}
