package control

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const (
	AgentsPath        = "/v1/agents"
	AgentSearch       = "/v1/agents/search"
	AgentPath         = "/v1/agents/{id}"
	AgentHistory      = "/v1/agents/{id}/history"
	AgentTransition   = "/v1/agents/{id}/transition"
	AgentIdentityPath = "/v1/agents/{id}/identity"
)

// Where the platform keeps what it decided about the machines it takes telemetry
// from. It owns no store and no driver: the registry is chosen by an executable,
// and every call carries the tenants the policy granted this caller rather than
// a filter they supplied.
type Agents interface {
	Register(ctx context.Context, asked *agentv1.Registration, actor string, at time.Time) (*agentv1.Agent, error)
	Page(ctx context.Context, asked *agentv1.Query, tenants []string) (*agentv1.Page, error)
	Agent(ctx context.Context, id string, tenants []string) (*agentv1.Agent, error)
	History(ctx context.Context, id string, tenants []string) (*agentv1.History, error)
	Move(ctx context.Context, id string, tenants []string, asked agent.Move) (*agentv1.Agent, error)
	Outstanding(ctx context.Context, limit int) ([]*agentv1.Admission, error)
	Announced(ctx context.Context, agentID string, revision uint64) error
}

// A tenant is not a field a caller fills in: registering an agent into an estate
// the caller does not hold is refused before the registry is reached, so the
// scope a machine's telemetry will carry is decided by the policy.
func (s *Server) registerAgent() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		var asked agentv1.Registration
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		decision := caller.Grant.DecideWithin(
			authz.Permission{Resource: authz.Agents, Action: authz.Write}, asked.GetTenantId())
		s.metrics.decided(decision)
		if !decision.Allowed() {
			Refuse(w, http.StatusForbidden, CodeForbidden,
				"registering an agent into "+asked.GetTenantId()+" needs "+decision.Permission.String()+" there")
			return
		}

		registered, err := s.agents.Register(r.Context(), &asked, caller.Subject, s.now())
		if err != nil {
			s.metrics.agentMoved("refused")
			s.refuseAgent(w, err)
			return
		}
		s.metrics.agentMoved(agentState(registered))
		s.announce(r.Context(), registered)

		respond(w, http.StatusCreated, registered)
	})
}

func (s *Server) searchAgents() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		var asked agentv1.Query
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}
		if err := agentFilters(&asked); err != nil {
			Refuse(w, http.StatusUnprocessableEntity, CodeUnknownFilter, err.Error())
			return
		}

		page, err := s.agents.Page(r.Context(), &asked, caller.Grant.Tenants())
		if err != nil {
			s.refuseAgent(w, err)
			return
		}
		s.observed(r.Context(), page.GetAgents(), caller.Grant.Tenants())
		respond(w, http.StatusOK, page)
	})
}

func (s *Server) describeAgent() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		one, err := s.agents.Agent(r.Context(), r.PathValue("id"), caller.Grant.Tenants())
		if err != nil {
			s.refuseAgent(w, err)
			return
		}
		s.observed(r.Context(), []*agentv1.Agent{one}, caller.Grant.Tenants())
		respond(w, http.StatusOK, one)
	})
}

func (s *Server) agentHistory() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		trail, err := s.agents.History(r.Context(), r.PathValue("id"), caller.Grant.Tenants())
		if err != nil {
			s.refuseAgent(w, err)
			return
		}
		respond(w, http.StatusOK, trail)
	})
}

func (s *Server) transitionAgent() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var asked agentv1.TransitionRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		to, known := agent.FromWire(asked.GetTo())
		if !known {
			Refuse(w, http.StatusUnprocessableEntity, CodeIllegalMove, "the request names no agent state to move to")
			return
		}
		s.moveAgent(w, r, agent.Move{To: to, Note: asked.GetNote(), Expected: asked.GetExpectedRevision()})
	})
}

func (s *Server) bindAgentIdentity() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var asked agentv1.BindingRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}
		s.moveAgent(w, r, agent.Move{
			Identity: asked.GetIdentity(),
			Note:     asked.GetNote(),
			Expected: asked.GetExpectedRevision(),
		})
	})
}

// The store decides the move under a held row and the log is written from what
// it decided, so what the data plane is told is what was recorded and never what
// a caller asked for.
func (s *Server) moveAgent(w http.ResponseWriter, r *http.Request, asked agent.Move) {
	caller, known := CallerFrom(r.Context())
	if !known {
		Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
		return
	}

	asked.Actor = caller.Subject
	asked.At = s.now()

	moved, err := s.agents.Move(r.Context(), r.PathValue("id"), caller.Grant.Tenants(), asked)
	if err != nil {
		s.metrics.agentMoved("refused")
		s.refuseAgent(w, err)
		return
	}
	s.metrics.agentMoved(agentState(moved))
	s.announce(r.Context(), moved)

	respond(w, http.StatusOK, moved)
}

func agentState(moved *agentv1.Agent) string {
	named, known := agent.FromWire(moved.GetState())
	if !known {
		return ""
	}
	return named.String()
}

func (s *Server) refuseAgent(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, agent.ErrUnknown):
		Refuse(w, http.StatusNotFound, CodeUnknownAgent, err.Error())
	case errors.Is(err, agent.ErrRegistered):
		Refuse(w, http.StatusConflict, CodeAgentRegistered, err.Error())
	case errors.Is(err, agent.ErrMoved):
		Refuse(w, http.StatusConflict, CodeAgentMoved, err.Error())
	case errors.Is(err, agent.ErrCursor):
		Refuse(w, http.StatusBadRequest, CodeBadCursor, err.Error())
	case agent.Refused(err):
		Refuse(w, http.StatusUnprocessableEntity, CodeIllegalMove, err.Error())
	default:
		s.unavailable(w, CodeAgentsUnavailable, err)
	}
}

func agentRoutes(s *Server) []route {
	return []route{
		{http.MethodPost, AgentsPath, "agent_register", Permits(authz.Agents, authz.Write), s.registerAgent()},
		{http.MethodPost, AgentSearch, "agent_search", Permits(authz.Agents, authz.Read), s.searchAgents()},
		{http.MethodGet, AgentPath, "agent_describe", Permits(authz.Agents, authz.Read), s.describeAgent()},
		{http.MethodGet, AgentHistory, "agent_history", Permits(authz.Agents, authz.Read), s.agentHistory()},
		{http.MethodPost, AgentTransition, "agent_transition", Permits(authz.Agents, authz.Write), s.transitionAgent()},
		{http.MethodPost, AgentIdentityPath, "agent_bind_identity", Permits(authz.Agents, authz.Write), s.bindAgentIdentity()},
	}
}
