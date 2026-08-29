package control

import (
	"crypto/x509"
	"io"
	"net/http"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

const ContentType = "application/x-protobuf"

// Sessions and nothing else: an endpoint that exists before its protections do
// is an endpoint that shipped unprotected.
const (
	SessionPath  = "/v1/auth/session"
	SessionsPath = "/v1/auth/sessions"
)

const MaxBodyBytes = 4 << 10

func clientCertificate(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

func Refuse(w http.ResponseWriter, status int, code, detail string) {
	encoded, err := proto.Marshal(&controlv1.Refusal{Code: code, Detail: detail})
	if err != nil {
		http.Error(w, code, status)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func respond(w http.ResponseWriter, status int, message proto.Message) {
	encoded, err := proto.Marshal(message)
	if err != nil {
		Refuse(w, http.StatusInternalServerError, "response_encoding_failed", "the answer could not be encoded")
		return
	}
	w.Header().Set("Content-Type", ContentType)
	// A session token must not be held by a proxy or a browser cache, and the
	// grant beside it goes stale the moment the policy changes.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func readWithin(w http.ResponseWriter, r *http.Request, into proto.Message, ceiling int64) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, ceiling))
	if err != nil {
		Refuse(w, http.StatusRequestEntityTooLarge, "body_too_large", "the request body is larger than this route reads")
		return false
	}
	if len(body) == 0 {
		return true
	}
	if err := proto.Unmarshal(body, into); err != nil {
		Refuse(w, http.StatusBadRequest, "unreadable_request", "the request body is not the message this route reads")
		return false
	}
	return true
}

func (s *Server) openSession() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoCertificate, "the request did not come through the guard")
			return
		}

		var asked controlv1.SessionRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		session, token, err := s.sessions.Open(caller.Subject, caller.Binding, s.now())
		if err != nil {
			Refuse(w, http.StatusServiceUnavailable, "session_refused", err.Error())
			return
		}
		s.metrics.sessionOpened(s.sessions.Live())

		respond(w, http.StatusCreated, &controlv1.SessionResponse{
			Token:   token,
			Session: describe(session, caller.Grant),
		})
	})
}

func (s *Server) describeSession() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		respond(w, http.StatusOK, describe(caller.Session, caller.Grant))
	})
}

func (s *Server) revokeSession() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		var asked controlv1.RevocationRequest
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}

		if asked.GetSessionId() == "" || asked.GetSessionId() == caller.Session.ID() {
			ended := s.sessions.Revoke(caller.Session.ID())
			s.metrics.sessionsEnded("caller", ended, s.sessions.Live())
			respond(w, http.StatusOK, &controlv1.RevocationResponse{Revoked: uint32(ended)})
			return
		}

		decision := caller.Grant.Decide(authz.Permission{Resource: authz.Sessions, Action: authz.Delete})
		s.metrics.decided(decision)
		if !decision.Allowed() {
			Refuse(w, http.StatusForbidden, CodeForbidden, "ending another caller's session needs "+decision.Permission.String())
			return
		}

		ended := s.sessions.Revoke(asked.GetSessionId())
		s.metrics.sessionsEnded("administrator", ended, s.sessions.Live())
		respond(w, http.StatusOK, &controlv1.RevocationResponse{Revoked: uint32(ended)})
	})
}

func describe(session authz.Session, grant authz.Grant) *controlv1.Session {
	described := &controlv1.Session{Id: session.ID(), Grant: grantOf(grant)}
	if !session.IssuedAt().IsZero() {
		described.IssuedAt = timestamppb.New(session.IssuedAt())
	}
	if !session.ExpiresAt().IsZero() {
		described.ExpiresAt = timestamppb.New(session.ExpiresAt())
	}
	return described
}

func grantOf(grant authz.Grant) *controlv1.Grant {
	held := grant.Permissions()
	permissions := make([]*controlv1.Permission, 0, len(held))
	for _, permission := range held {
		resource, known := resources[permission.Resource]
		action, verb := actions[permission.Action]
		if !known || !verb {
			continue
		}
		permissions = append(permissions, &controlv1.Permission{Resource: resource, Action: action})
	}

	return &controlv1.Grant{
		Subject:     grant.Subject(),
		Tenants:     grant.Tenants(),
		Roles:       grant.Roles(),
		Permissions: permissions,
	}
}

// Mapped explicitly in both directions rather than by name, so that renaming a
// constant on either side is a compile error here instead of a silent change in
// what a caller is told they hold.
var resources = map[authz.Resource]controlv1.Resource{
	authz.Events:     controlv1.Resource_RESOURCE_EVENTS,
	authz.Detections: controlv1.Resource_RESOURCE_DETECTIONS,
	authz.Rulesets:   controlv1.Resource_RESOURCE_RULESETS,
	authz.Alerts:     controlv1.Resource_RESOURCE_ALERTS,
	authz.Agents:     controlv1.Resource_RESOURCE_AGENTS,
	authz.Policies:   controlv1.Resource_RESOURCE_POLICIES,
	authz.Sessions:   controlv1.Resource_RESOURCE_SESSIONS,
}

var actions = map[authz.Action]controlv1.Action{
	authz.Read:   controlv1.Action_ACTION_READ,
	authz.Write:  controlv1.Action_ACTION_WRITE,
	authz.Delete: controlv1.Action_ACTION_DELETE,
}

func (s *Server) listSessions() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		subject := r.URL.Query().Get("subject")
		if subject == "" {
			subject = caller.Subject
		}
		if subject != caller.Subject {
			decision := caller.Grant.Decide(authz.Permission{Resource: authz.Sessions, Action: authz.Read})
			s.metrics.decided(decision)
			if !decision.Allowed() {
				Refuse(w, http.StatusForbidden, CodeForbidden, "reading another caller's sessions needs "+decision.Permission.String())
				return
			}
		}

		held := s.sessions.Held(subject)
		listed := make([]*controlv1.Session, 0, len(held))
		for _, record := range held {
			listed = append(listed, &controlv1.Session{
				Id:        record.ID,
				IssuedAt:  timestamppb.New(record.IssuedAt),
				ExpiresAt: timestamppb.New(record.ExpiresAt),
				Grant:     &controlv1.Grant{Subject: record.Subject},
			})
		}
		respond(w, http.StatusOK, &controlv1.SessionList{Sessions: listed})
	})
}
