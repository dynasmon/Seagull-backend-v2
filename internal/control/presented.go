package control

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
)

const DefaultReplacedTolerance = time.Minute

// The agent listener reads the registry itself, so it is never behind a renewal
// and admits an agent only on the certificate in force, or on the one it
// replaced for the tolerance after the registry bound the next. Only that is
// answered here: an agent the registry does not know or no longer admits is
// answered by the route as before, and so is every agent on its certificate in
// force. A connection that presented any other certificate is closed once it is
// answered, so an agent that renewed opens its next one on what it renewed into.
func (s *Server) presents(w http.ResponseWriter, r *http.Request, presented agentidentity.Identity, route string) bool {
	state, binding, err := s.agents.Binding(r.Context(), presented.AgentID)
	switch {
	case errors.Is(err, agent.ErrUnknown):
		return true
	case err != nil:
		s.unavailable(w, CodeAgentsUnavailable, err)
		return false
	case !state.Admits():
		return true
	}

	now := s.now()
	switch binding.Judge(presented.Certificate, time.Time{}, now, s.tolerance) {
	case agentidentity.Unbound, agentidentity.InForce:
		return true
	case agentidentity.Tolerated:
		s.metrics.certificatePresented("tolerated")
		w.Header().Set("Connection", "close")
		return true
	}

	s.metrics.certificatePresented("replaced")
	if err := s.agents.ReplacedUsed(r.Context(), presented.AgentID, binding.Fingerprint, route, now); err != nil {
		s.logger.Warn("agent_replaced_certificate_unrecorded", slog.String("agent_id", presented.AgentID), slog.String("error", err.Error()))
	}
	s.logger.Warn("agent_certificate_refused", slog.String("agent_id", presented.AgentID), slog.String("route", route),
		slog.String("reason", "replaced"))
	w.Header().Set("Connection", "close")
	Refuse(w, http.StatusForbidden, CodeCertificateReplaced,
		"the certificate this connection presents is not the one the registry binds this agent to")
	return false
}
