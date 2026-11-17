package control

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/disposition"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

const (
	DispositionsPath      = "/v1/vulnerabilities/dispositions"
	DispositionSearch     = "/v1/vulnerabilities/dispositions/search"
	DispositionWithdrawal = "/v1/vulnerabilities/dispositions/{id}/withdrawal"
)

// Where what people decided about vulnerabilities is kept. It owns no store and
// no driver, and every call carries the tenants the policy granted this caller
// rather than a filter they supplied.
type Dispositions interface {
	Record(ctx context.Context, recorded *vulnerabilityv1.Disposition) error
	Withdraw(ctx context.Context, id string, tenants []string, withdrawal disposition.Withdrawal) (*vulnerabilityv1.Disposition, error)
	Page(ctx context.Context, asked *vulnerabilityv1.DispositionQuery, tenants []string, at time.Time) (*vulnerabilityv1.DispositionPage, error)
}

// The tenant is decided by the policy before anything else is read, and the
// actor and the instant are this listener's: none of them is the caller's to
// write.
func (s *Server) recordDisposition() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		var asked vulnerabilityv1.DispositionRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		decision := caller.Grant.DecideWithin(
			authz.Permission{Resource: authz.Vulnerabilities, Action: authz.Write}, asked.GetTenantId())
		s.metrics.decided(decision)
		if !decision.Allowed() {
			Refuse(w, http.StatusForbidden, CodeForbidden,
				"deciding about a vulnerability of "+asked.GetTenantId()+" needs "+decision.Permission.String()+" there")
			return
		}

		recorded, err := disposition.Record(&asked, caller.Subject, s.now())
		if err == nil {
			err = s.dispositions.Record(r.Context(), recorded)
		}
		if err != nil {
			s.metrics.disposed("refused")
			s.refuseDisposition(w, err)
			return
		}
		kind, _ := disposition.KindOf(recorded.GetKind())
		s.metrics.disposed(kind.String())
		s.logger.Info("vulnerability_disposition_recorded",
			slog.String("disposition_id", recorded.GetDispositionId()),
			slog.String("tenant_id", recorded.GetTenantId()),
			slog.String("vulnerability_id", recorded.GetVulnerabilityId()),
			slog.String("agent_id", recorded.GetAgentId()),
			slog.String("kind", kind.String()),
			slog.Time("expires_at", recorded.GetExpiresAt().AsTime()),
			slog.String("actor", recorded.GetActor()),
		)
		respond(w, http.StatusCreated, recorded)
	})
}

func (s *Server) withdrawDisposition() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		var asked vulnerabilityv1.WithdrawalRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		withdrawn, err := s.dispositions.Withdraw(r.Context(), r.PathValue("id"), caller.Grant.Tenants(),
			disposition.Withdrawal{Reason: asked.GetReason(), Actor: caller.Subject, At: s.now()})
		if err != nil {
			s.metrics.disposed("refused")
			s.refuseDisposition(w, err)
			return
		}
		s.metrics.disposed("withdrawn")
		s.logger.Info("vulnerability_disposition_withdrawn",
			slog.String("disposition_id", withdrawn.GetDispositionId()),
			slog.String("tenant_id", withdrawn.GetTenantId()),
			slog.String("vulnerability_id", withdrawn.GetVulnerabilityId()),
			slog.String("actor", withdrawn.GetWithdrawnBy()),
		)
		respond(w, http.StatusOK, withdrawn)
	})
}

func (s *Server) searchDispositions() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		var asked vulnerabilityv1.DispositionQuery
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}
		if err := dispositionFilters(&asked); err != nil {
			Refuse(w, http.StatusUnprocessableEntity, CodeUnknownFilter, err.Error())
			return
		}

		page, err := s.dispositions.Page(r.Context(), &asked, caller.Grant.Tenants(), s.now())
		if err != nil {
			s.refuseDisposition(w, err)
			return
		}
		respond(w, http.StatusOK, page)
	})
}

func (s *Server) refuseDisposition(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, disposition.ErrUnknown):
		Refuse(w, http.StatusNotFound, CodeUnknownDisposition, err.Error())
	case errors.Is(err, disposition.ErrLapsed):
		Refuse(w, http.StatusConflict, CodeDispositionLapsed, err.Error())
	case errors.Is(err, disposition.ErrUnregistered):
		Refuse(w, http.StatusUnprocessableEntity, CodeDispositionUnregistered, err.Error())
	case errors.Is(err, disposition.ErrCursor):
		Refuse(w, http.StatusBadRequest, CodeBadCursor, err.Error())
	case errors.Is(err, disposition.ErrMalformed), errors.Is(err, disposition.ErrNoActor):
		Refuse(w, http.StatusUnprocessableEntity, CodeMalformedDisposition, err.Error())
	default:
		s.unavailable(w, CodeDispositionsUnavailable, err)
	}
}

func dispositionRoutes(s *Server) []route {
	return []route{
		{http.MethodPost, DispositionsPath, "disposition_record", Permits(authz.Vulnerabilities, authz.Write), s.recordDisposition()},
		{http.MethodPost, DispositionSearch, "disposition_search", Permits(authz.Vulnerabilities, authz.Read), s.searchDispositions()},
		{http.MethodPost, DispositionWithdrawal, "disposition_withdraw", Permits(authz.Vulnerabilities, authz.Write), s.withdrawDisposition()},
	}
}
