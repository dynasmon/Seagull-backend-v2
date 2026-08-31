package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
)

const (
	AlertSearch     = "/v1/alerts/search"
	AlertPath       = "/v1/alerts/{id}"
	AlertHistory    = "/v1/alerts/{id}/history"
	AlertMadeOf     = "/v1/alerts/{id}/occurrences"
	AlertTransition = "/v1/alerts/{id}/transition"
	AlertAssignment = "/v1/alerts/{id}/assignment"
)

// What the control plane can do about alerts. It owns no store and no driver:
// where an alert is kept is chosen by an executable, and every call carries the
// tenants the policy granted this caller rather than a filter they supplied.
type Alerts interface {
	Page(ctx context.Context, asked *alertv1.Query, tenants []string) (*alertv1.Page, error)
	Alert(ctx context.Context, id string, tenants []string) (*alertv1.Alert, error)
	History(ctx context.Context, id string, tenants []string) (*alertv1.History, error)
	Occurrences(ctx context.Context, id string, tenants []string) (*alertv1.Occurrences, error)
	Move(ctx context.Context, id string, tenants []string, asked alert.Move) (*alertv1.Alert, error)
}

func (s *Server) searchAlerts() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		var asked alertv1.Query
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		page, err := s.alerts.Page(r.Context(), &asked, caller.Grant.Tenants())
		if err != nil {
			s.refuseAlert(w, err)
			return
		}
		respond(w, http.StatusOK, page)
	})
}

func (s *Server) describeAlert() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		one, err := s.alerts.Alert(r.Context(), r.PathValue("id"), caller.Grant.Tenants())
		if err != nil {
			s.refuseAlert(w, err)
			return
		}
		respond(w, http.StatusOK, one)
	})
}

func (s *Server) alertHistory() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		trail, err := s.alerts.History(r.Context(), r.PathValue("id"), caller.Grant.Tenants())
		if err != nil {
			s.refuseAlert(w, err)
			return
		}
		respond(w, http.StatusOK, trail)
	})
}

// Folding raises a count and discards nothing, so the count can always be read
// back to the detections behind it and from there to their evidence.
func (s *Server) alertOccurrences() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		made, err := s.alerts.Occurrences(r.Context(), r.PathValue("id"), caller.Grant.Tenants())
		if err != nil {
			s.refuseAlert(w, err)
			return
		}
		respond(w, http.StatusOK, made)
	})
}

func (s *Server) transitionAlert() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var asked alertv1.TransitionRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		to, known := alert.FromWire(asked.GetTo())
		if !known {
			Refuse(w, http.StatusUnprocessableEntity, CodeIllegalMove, "the request names no alert state to move to")
			return
		}
		s.move(w, r, alert.Move{To: to, Note: asked.GetNote(), Expected: asked.GetExpectedRevision()})
	})
}

func (s *Server) assignAlert() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var asked alertv1.AssignmentRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}
		s.move(w, r, alert.Move{
			Assignee: alert.Assigning(asked.GetAssignee()),
			Note:     asked.GetNote(),
			Expected: asked.GetExpectedRevision(),
		})
	})
}

// The alert is read before the move is decided, and the move is then conditioned
// on the revision that read returned: the authority decision and the write are
// about the same alert, so an alert reassigned in between is refused rather than
// acted on under an answer that is no longer true.
func (s *Server) move(w http.ResponseWriter, r *http.Request, asked alert.Move) {
	caller, known := CallerFrom(r.Context())
	if !known {
		Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
		return
	}

	id := r.PathValue("id")
	tenants := caller.Grant.Tenants()
	held, err := s.alerts.Alert(r.Context(), id, tenants)
	if err != nil {
		s.refuseAlert(w, err)
		return
	}

	if holder := held.GetAssignee(); holder != "" && holder != caller.Subject {
		decision := caller.Grant.Decide(authz.Permission{Resource: authz.Alerts, Action: authz.Delete})
		s.metrics.decided(decision)
		if !decision.Allowed() {
			Refuse(w, http.StatusForbidden, CodeHeldByAnother,
				"this alert is held by "+holder+" and acting on it needs "+decision.Permission.String())
			return
		}
	}

	asked.Actor = caller.Subject
	asked.At = s.now()
	if asked.Expected == 0 {
		asked.Expected = held.GetRevision()
	}

	moved, err := s.alerts.Move(r.Context(), id, tenants, asked)
	if err != nil {
		s.metrics.alertMoved("refused")
		s.refuseAlert(w, err)
		return
	}
	s.metrics.alertMoved(state(moved))
	respond(w, http.StatusOK, moved)
}

func state(moved *alertv1.Alert) string {
	named, known := alert.FromWire(moved.GetState())
	if !known {
		return ""
	}
	return named.String()
}

func (s *Server) refuseAlert(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, alert.ErrUnknownAlert):
		Refuse(w, http.StatusNotFound, CodeUnknownAlert, err.Error())
	case errors.Is(err, alert.ErrMoved):
		Refuse(w, http.StatusConflict, CodeAlertMoved, err.Error())
	case errors.Is(err, alert.ErrCursor):
		Refuse(w, http.StatusBadRequest, CodeBadCursor, err.Error())
	case alert.Refused(err):
		Refuse(w, http.StatusUnprocessableEntity, CodeIllegalMove, err.Error())
	default:
		Refuse(w, http.StatusServiceUnavailable, CodeAlertsUnavailable, err.Error())
	}
}

func alertRoutes(s *Server) []route {
	return []route{
		{http.MethodPost, AlertSearch, "alert_search", Permits(authz.Alerts, authz.Read), s.searchAlerts()},
		{http.MethodGet, AlertPath, "alert_describe", Permits(authz.Alerts, authz.Read), s.describeAlert()},
		{http.MethodGet, AlertHistory, "alert_history", Permits(authz.Alerts, authz.Read), s.alertHistory()},
		{http.MethodGet, AlertMadeOf, "alert_occurrences", Permits(authz.Alerts, authz.Read), s.alertOccurrences()},
		{http.MethodPost, AlertTransition, "alert_transition", Permits(authz.Alerts, authz.Write), s.transitionAlert()},
		{http.MethodPost, AlertAssignment, "alert_assign", Permits(authz.Alerts, authz.Write), s.assignAlert()},
	}
}
