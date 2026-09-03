package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
)

// Authentication and authorisation carry different codes at different statuses:
// "I do not know who you are" and "I know who you are and the answer is no" are
// different incidents.
const (
	CodeNoCertificate     = "no_client_certificate"
	CodeUnknownSubject    = "unknown_subject"
	CodeNoSession         = "no_session"
	CodeInvalidToken      = "invalid_token"
	CodeSessionExpired    = "session_expired"
	CodeSessionRevoked    = "session_revoked"
	CodeWrongCertificate  = "wrong_certificate"
	CodeNoGrant           = "no_grant"
	CodeForbidden         = "forbidden"
	CodeRateLimited       = "rate_limited"
	CodeUnguarded         = "route_unguarded"
	CodeNoDocuments       = "no_documents"
	CodeUnknownRuleset    = "unknown_ruleset"
	CodePublishFailed     = "ruleset_not_published"
	CodeActivationFailed  = "ruleset_not_activated"
	CodeUnknownAlert      = "unknown_alert"
	CodeAlertMoved        = "alert_moved"
	CodeIllegalMove       = "illegal_move"
	CodeHeldByAnother     = "alert_held_by_another"
	CodeBadCursor         = "invalid_cursor"
	CodeAlertsUnavailable = "alerts_unavailable"

	CodeUnknownIncident      = "unknown_incident"
	CodeIncidentMoved        = "incident_moved"
	CodeStoryHeldByAnother   = "incident_held_by_another"
	CodeIncidentsUnavailable = "incidents_unavailable"
)

// No value of this type means "anybody": the zero value refuses, so a route
// nobody thought about is closed rather than open.
type Requirement struct {
	need       need
	permission authz.Permission
}

type need uint8

const (
	needNothing need = iota
	needCertificate
	needSession
	needPermission
)

func Certificate() Requirement { return Requirement{need: needCertificate} }

func Session() Requirement { return Requirement{need: needSession} }

func Permits(resource authz.Resource, action authz.Action) Requirement {
	return Requirement{need: needPermission, permission: authz.Permission{Resource: resource, Action: action}}
}

func (r Requirement) valid() bool { return r.need != needNothing }

func (r Requirement) Permission() authz.Permission { return r.permission }

type Caller struct {
	Subject string
	Session authz.Session
	Grant   authz.Grant

	Binding [sha256.Size]byte
}

type callerKey struct{}

func CallerFrom(ctx context.Context) (Caller, bool) {
	caller, ok := ctx.Value(callerKey{}).(Caller)
	return caller, ok
}

type GuardOptions struct {
	Sessions *Sessions
	Registry *Registry
	Limiter  *ratelimit.Limiter
	Metrics  *Metrics
	Logger   *slog.Logger
	Now      func() time.Time
}

type Guard struct {
	sessions *Sessions
	registry *Registry
	limiter  *ratelimit.Limiter
	metrics  *Metrics
	logger   *slog.Logger
	now      func() time.Time
}

func NewGuard(options GuardOptions) (*Guard, error) {
	switch {
	case options.Sessions == nil:
		return nil, errors.New("a guard needs somewhere to read sessions from")
	case options.Registry == nil:
		return nil, errors.New("a guard needs a policy to decide against")
	case options.Metrics == nil:
		return nil, errors.New("a guard needs metrics: a refusal nobody counts is one nobody notices")
	case options.Logger == nil:
		return nil, errors.New("a guard needs a logger: authentication failures have to be auditable")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Guard{
		sessions: options.Sessions,
		registry: options.Registry,
		limiter:  options.Limiter,
		metrics:  options.Metrics,
		logger:   options.Logger,
		now:      options.Now,
	}, nil
}

func (g *Guard) Handle(route string, requirement Requirement, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, refusal := g.admit(r, requirement)
		if refusal != nil {
			g.refuse(w, r, route, caller.Subject, refusal)
			return
		}

		g.audit(r, route, caller, requirement)
		next.ServeHTTP(w, r.WithContext(context.WithValue(
			log.With(r.Context(), slog.String("subject", caller.Subject)),
			callerKey{}, caller,
		)))
	})
}

type refusal struct {
	status int
	code   string
	detail string
}

func (g *Guard) admit(r *http.Request, requirement Requirement) (Caller, *refusal) {
	if !requirement.valid() {
		return Caller{}, &refusal{http.StatusInternalServerError, CodeUnguarded, "this route was registered without saying what it requires"}
	}

	certificate := clientCertificate(r)
	if certificate == nil {
		g.metrics.authenticated(CodeNoCertificate)
		return Caller{}, &refusal{http.StatusUnauthorized, CodeNoCertificate, "the connection carries no verified client certificate"}
	}

	caller := Caller{Subject: certificate.Subject.CommonName, Binding: authz.Fingerprint(certificate)}
	if !authz.ValidSubject(caller.Subject) {
		g.metrics.authenticated(CodeUnknownSubject)
		return Caller{}, &refusal{http.StatusUnauthorized, CodeUnknownSubject, "the certificate carries no usable subject"}
	}

	// Spent before the session is read, so that a caller cannot use a flood of
	// tokens to make the process do signature work on their behalf.
	if g.limiter != nil && !g.limiter.Allow(caller.Subject) {
		g.metrics.limited()
		return caller, &refusal{http.StatusTooManyRequests, CodeRateLimited, "this caller is spending more than its share"}
	}

	if token, offered := bearer(r); offered {
		session, err := g.sessions.Verify(token, caller.Binding, g.now())
		if err != nil {
			return caller, g.tokenRefusal(err)
		}
		if session.Subject() != caller.Subject {
			g.metrics.authenticated(CodeWrongCertificate)
			return caller, &refusal{http.StatusUnauthorized, CodeWrongCertificate, "the token names a different caller than the certificate"}
		}
		caller.Session = session
	} else if requirement.need != needCertificate {
		g.metrics.authenticated(CodeNoSession)
		return caller, &refusal{http.StatusUnauthorized, CodeNoSession, "this route needs a session; open one first"}
	}

	g.metrics.authenticated("allowed")

	// Resolved per request from the current policy, never read out of the token,
	// so a role taken away is gone at the next request.
	grant, err := g.registry.Current().Grant(caller.Subject)
	if err != nil {
		decision := authz.Decision{Reason: authz.NoGrant, Permission: requirement.permission}
		g.metrics.decided(decision)
		return caller, &refusal{http.StatusForbidden, CodeNoGrant, "the policy binds no roles to this caller"}
	}
	caller.Grant = grant

	if requirement.need != needPermission {
		return caller, nil
	}

	decision := grant.Decide(requirement.permission)
	g.metrics.decided(decision)
	if !decision.Allowed() {
		return caller, &refusal{http.StatusForbidden, CodeForbidden, "this caller does not hold " + requirement.permission.String()}
	}
	return caller, nil
}

func (g *Guard) tokenRefusal(err error) *refusal {
	switch {
	case errors.Is(err, authz.ErrExpired):
		g.metrics.authenticated(CodeSessionExpired)
		return &refusal{http.StatusUnauthorized, CodeSessionExpired, "the session has expired; open another"}
	case errors.Is(err, ErrRevoked):
		g.metrics.authenticated(CodeSessionRevoked)
		return &refusal{http.StatusUnauthorized, CodeSessionRevoked, "the session was ended; open another"}
	case errors.Is(err, authz.ErrWrongCertificate):
		g.metrics.authenticated(CodeWrongCertificate)
		return &refusal{http.StatusUnauthorized, CodeWrongCertificate, "the token was issued to a different certificate"}
	default:
		g.metrics.authenticated(CodeInvalidToken)
		return &refusal{http.StatusUnauthorized, CodeInvalidToken, "the token was not issued here"}
	}
}

func (g *Guard) refuse(w http.ResponseWriter, r *http.Request, route, subject string, why *refusal) {
	g.logger.WarnContext(r.Context(), "control_request_refused",
		slog.String("route", route),
		slog.String("subject", subject),
		slog.String("code", why.code),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", why.status),
	)
	Refuse(w, why.status, why.code, why.detail)
}

func (g *Guard) audit(r *http.Request, route string, caller Caller, requirement Requirement) {
	attributes := []any{
		slog.String("route", route),
		slog.String("subject", caller.Subject),
		slog.String("policy", g.registry.Current().ID().String()),
	}
	if !caller.Session.Empty() {
		attributes = append(attributes, slog.String("session", caller.Session.ID()))
	}
	if requirement.need == needPermission {
		attributes = append(attributes, slog.String("permission", requirement.permission.String()))
	}
	g.logger.InfoContext(r.Context(), "control_request_allowed", attributes...)
}

func bearer(r *http.Request) (string, bool) {
	written := r.Header.Get("Authorization")
	if written == "" {
		return "", false
	}
	scheme, token, found := strings.Cut(written, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return written, true
	}
	return strings.TrimSpace(token), true
}
