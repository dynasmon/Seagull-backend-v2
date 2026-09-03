package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

const (
	IncidentSearch     = "/v1/incidents/search"
	IncidentPath       = "/v1/incidents/{id}"
	IncidentHistory    = "/v1/incidents/{id}/history"
	IncidentTransition = "/v1/incidents/{id}/transition"
	IncidentAssignment = "/v1/incidents/{id}/assignment"
)

// What the control plane can do about incidents. A port of its own beside the
// one alerts take: reaching a story and reaching a piece of work are separately
// granted, so a caller who may work alerts is not thereby able to close the
// correlation that grouped them.
type Incidents interface {
	Page(ctx context.Context, asked *incidentv1.Query, tenants []string) (*incidentv1.Page, error)
	Incident(ctx context.Context, id string, tenants []string) (*incidentv1.Incident, error)
	History(ctx context.Context, id string, tenants []string) (*incidentv1.History, error)
	Move(ctx context.Context, id string, tenants []string, asked incident.Move) (*incidentv1.Incident, error)
}

func (s *Server) searchIncidents() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		var asked incidentv1.Query
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		page, err := s.incidents.Page(r.Context(), &asked, caller.Grant.Tenants())
		if err != nil {
			s.refuseIncident(w, err)
			return
		}
		respond(w, http.StatusOK, page)
	})
}

// The stages are on the incident rather than behind a route of their own: a
// story names one event per stage and a rule bounds how many stages it may
// have, so what an incident is made of is small enough to answer with it.
func (s *Server) describeIncident() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		one, err := s.incidents.Incident(r.Context(), r.PathValue("id"), caller.Grant.Tenants())
		if err != nil {
			s.refuseIncident(w, err)
			return
		}
		respond(w, http.StatusOK, one)
	})
}

func (s *Server) incidentHistory() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		trail, err := s.incidents.History(r.Context(), r.PathValue("id"), caller.Grant.Tenants())
		if err != nil {
			s.refuseIncident(w, err)
			return
		}
		respond(w, http.StatusOK, trail)
	})
}

func (s *Server) transitionIncident() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var asked incidentv1.TransitionRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		to, known := incident.FromWire(asked.GetTo())
		if !known {
			Refuse(w, http.StatusUnprocessableEntity, CodeIllegalMove, "the request names no incident state to move to")
			return
		}
		s.moveIncident(w, r, incident.Move{To: to, Note: asked.GetNote(), Expected: asked.GetExpectedRevision()})
	})
}

func (s *Server) assignIncident() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var asked incidentv1.AssignmentRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}
		s.moveIncident(w, r, incident.Move{
			Assignee: incident.Assigning(asked.GetAssignee()),
			Note:     asked.GetNote(),
			Expected: asked.GetExpectedRevision(),
		})
	})
}

// The incident is read before the move is decided, and the move is then
// conditioned on the revision that read returned: the authority decision and the
// write are about the same story, so one reassigned in between is refused rather
// than acted on under an answer that is no longer true.
func (s *Server) moveIncident(w http.ResponseWriter, r *http.Request, asked incident.Move) {
	caller, known := CallerFrom(r.Context())
	if !known {
		Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
		return
	}

	id := r.PathValue("id")
	tenants := caller.Grant.Tenants()
	held, err := s.incidents.Incident(r.Context(), id, tenants)
	if err != nil {
		s.refuseIncident(w, err)
		return
	}

	if holder := held.GetAssignee(); holder != "" && holder != caller.Subject {
		decision := caller.Grant.Decide(authz.Permission{Resource: authz.Incidents, Action: authz.Delete})
		s.metrics.decided(decision)
		if !decision.Allowed() {
			Refuse(w, http.StatusForbidden, CodeStoryHeldByAnother,
				"this incident is held by "+holder+" and acting on it needs "+decision.Permission.String())
			return
		}
	}

	asked.Actor = caller.Subject
	asked.At = s.now()
	if asked.Expected == 0 {
		asked.Expected = held.GetRevision()
	}

	moved, err := s.incidents.Move(r.Context(), id, tenants, asked)
	if err != nil {
		s.metrics.incidentMoved("refused")
		s.refuseIncident(w, err)
		return
	}
	s.metrics.incidentMoved(storyState(moved))
	respond(w, http.StatusOK, moved)
}

func storyState(moved *incidentv1.Incident) string {
	named, known := incident.FromWire(moved.GetState())
	if !known {
		return ""
	}
	return named.String()
}

func (s *Server) refuseIncident(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, incident.ErrUnknownIncident):
		Refuse(w, http.StatusNotFound, CodeUnknownIncident, err.Error())
	case errors.Is(err, incident.ErrMoved):
		Refuse(w, http.StatusConflict, CodeIncidentMoved, err.Error())
	case errors.Is(err, incident.ErrCursor):
		Refuse(w, http.StatusBadRequest, CodeBadCursor, err.Error())
	case incident.Refused(err):
		Refuse(w, http.StatusUnprocessableEntity, CodeIllegalMove, err.Error())
	default:
		Refuse(w, http.StatusServiceUnavailable, CodeIncidentsUnavailable, err.Error())
	}
}

func incidentRoutes(s *Server) []route {
	return []route{
		{http.MethodPost, IncidentSearch, "incident_search", Permits(authz.Incidents, authz.Read), s.searchIncidents()},
		{http.MethodGet, IncidentPath, "incident_describe", Permits(authz.Incidents, authz.Read), s.describeIncident()},
		{http.MethodGet, IncidentHistory, "incident_history", Permits(authz.Incidents, authz.Read), s.incidentHistory()},
		{http.MethodPost, IncidentTransition, "incident_transition", Permits(authz.Incidents, authz.Write), s.transitionIncident()},
		{http.MethodPost, IncidentAssignment, "incident_assign", Permits(authz.Incidents, authz.Write), s.assignIncident()},
	}
}
