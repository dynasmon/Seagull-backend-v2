package control

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const (
	AgentPoliciesPath = "/v1/agents/policies"
	AgentPolicySearch = "/v1/agents/policies/search"
	AgentPolicyPath   = "/v1/agents/policies/{tenant}/{revision}"
	PolicyPath        = "/v1/agents/policy"

	MaxPolicyBodyBytes = agentpolicy.MaxEnvelopeBytes + 4<<10
)

// Where the platform keeps the policies it was handed. It signs none of them:
// what is stored was verified against keys the platform holds only the public
// half of, and an agent verifies it again against its own.
type AgentPolicies interface {
	Publish(ctx context.Context, accepted agentpolicy.Accepted) (*policyv1.PublishedPolicy, error)
	Page(ctx context.Context, asked *policyv1.Query, tenants []string) (*policyv1.Page, error)
	Policy(ctx context.Context, tenant string, revision uint64, tenants []string) (*policyv1.PublishedPolicy, error)
	Served(ctx context.Context, agentID string) (agentpolicy.Served, error)
}

func (s *Server) publishPolicy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		var asked policyv1.Publication
		if !readWithin(w, r, &asked, MaxPolicyBodyBytes) {
			return
		}

		decision := caller.Grant.DecideWithin(
			authz.Permission{Resource: authz.Agents, Action: authz.Write}, asked.GetTenantId())
		s.metrics.decided(decision)
		if !decision.Allowed() {
			Refuse(w, http.StatusForbidden, CodeForbidden,
				"publishing an agent policy into "+asked.GetTenantId()+" needs "+decision.Permission.String()+" there")
			return
		}
		if s.policySigners == nil {
			s.metrics.policyPublished("unconfigured")
			Refuse(w, http.StatusServiceUnavailable, CodePoliciesUnconfigured,
				"this control plane was given no keys to verify an agent policy with, so it publishes none")
			return
		}
		signers, err := s.policySigners()
		if err != nil {
			s.metrics.policyPublished("unconfigured")
			s.unavailable(w, CodePoliciesUnconfigured, err)
			return
		}

		accepted, err := agentpolicy.Accept(&asked, signers, caller.Subject, s.now())
		if err != nil {
			s.metrics.policyPublished("refused")
			s.refusePolicy(w, err)
			return
		}
		recorded, err := s.policies.Publish(r.Context(), accepted)
		if err != nil {
			s.metrics.policyPublished("refused")
			s.refusePolicy(w, err)
			return
		}
		s.metrics.policyPublished("published")
		s.logger.Info("agent_policy_published",
			slog.String("tenant_id", recorded.GetTenantId()),
			slog.Uint64("revision", recorded.GetRevision()),
			slog.String("policy_id", recorded.GetPolicyId()),
			slog.Uint64("targets", uint64(recorded.GetTargets())),
			slog.String("digest_sha256", recorded.GetDigestSha256()),
			slog.Any("signed_by", recorded.GetSignedBy()),
			slog.String("published_by", recorded.GetPublishedBy()),
			slog.Time("expires_at", recorded.GetExpiresAt().AsTime()),
		)

		answered, _ := proto.Clone(recorded).(*policyv1.PublishedPolicy)
		answered.Policy = nil
		respond(w, http.StatusCreated, answered)
	})
}

func (s *Server) searchPolicies() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		var asked policyv1.Query
		if !readWithin(w, r, &asked, MaxBodyBytes) {
			return
		}
		page, err := s.policies.Page(r.Context(), &asked, caller.Grant.Tenants())
		if err != nil {
			s.refusePolicy(w, err)
			return
		}
		respond(w, http.StatusOK, page)
	})
}

func (s *Server) describePolicy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}

		revision, err := strconv.ParseUint(r.PathValue("revision"), 10, 64)
		if err != nil {
			s.refusePolicy(w, agentpolicy.ErrUnknown)
			return
		}
		published, err := s.policies.Policy(r.Context(), r.PathValue("tenant"), revision, caller.Grant.Tenants())
		if err != nil {
			s.refusePolicy(w, err)
			return
		}
		respond(w, http.StatusOK, published)
	})
}

// The agent is whoever the connection proved, and what it is handed is the
// envelope exactly as it was recorded. The platform vouches for nothing in it:
// the agent checks the signature against keys it was given out of band, and a
// platform that answers with anything else is refused by every agent.
func (s *Server) servePolicy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, err := agentidentity.FromConnection(r.TLS)
		if err != nil {
			s.metrics.policyServed("unidentified")
			Refuse(w, http.StatusUnauthorized, CodeNoCertificate, err.Error())
			return
		}
		if s.policyPulls != nil && !s.policyPulls.Allow(presented.AgentID) {
			s.metrics.policyServed("rate_limited")
			Refuse(w, http.StatusTooManyRequests, CodeRateLimited, "this agent is asking for its policy too often")
			return
		}

		served, err := s.policies.Served(r.Context(), presented.AgentID)
		switch {
		case errors.Is(err, agent.ErrUnknown):
			s.metrics.policyServed("unknown")
			Refuse(w, http.StatusNotFound, CodeUnknownAgent, "no agent is registered under the identity this connection proved")
			return
		case err != nil:
			s.metrics.policyServed("unavailable")
			s.unavailable(w, CodePoliciesUnavailable, err)
			return
		case !served.State.Admits():
			s.metrics.policyServed("not_admitted")
			Refuse(w, http.StatusForbidden, CodeNotAdmitted, "the platform no longer listens to this agent")
			return
		case !served.Named():
			s.metrics.policyServed("none")
			Refuse(w, http.StatusNotFound, CodeNoPolicy, "no policy published into this agent's tenant names it")
			return
		}

		tag := strconv.Quote(served.Digest)
		w.Header().Set("ETag", tag)
		w.Header().Set("Cache-Control", "no-store")
		if unchanged(r.Header.Get("If-None-Match"), tag) {
			s.metrics.policyServed("unchanged")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		s.metrics.policyServed("served")
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(served.Envelope)
	})
}

func unchanged(asked, tag string) bool {
	for candidate := range strings.SplitSeq(asked, ",") {
		candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "W/")
		if candidate == "*" || candidate == tag {
			return true
		}
	}
	return false
}

func (s *Server) refusePolicy(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, agentpolicy.ErrUnsigned):
		Refuse(w, http.StatusUnprocessableEntity, CodePolicyUnsigned, err.Error())
	case errors.Is(err, agentpolicy.ErrExpired):
		Refuse(w, http.StatusUnprocessableEntity, CodePolicyExpired, err.Error())
	case errors.Is(err, agentpolicy.ErrMalformed), errors.Is(err, agentpolicy.ErrNoActor):
		Refuse(w, http.StatusUnprocessableEntity, CodeMalformedPolicy, err.Error())
	case errors.Is(err, agentpolicy.ErrStale):
		Refuse(w, http.StatusConflict, CodePolicyStale, err.Error())
	case errors.Is(err, agentpolicy.ErrUnregistered):
		Refuse(w, http.StatusUnprocessableEntity, CodePolicyUnregistered, err.Error())
	case errors.Is(err, agentpolicy.ErrUnknown):
		Refuse(w, http.StatusNotFound, CodeUnknownPolicy, err.Error())
	case errors.Is(err, agentpolicy.ErrCursor):
		Refuse(w, http.StatusBadRequest, CodeBadCursor, err.Error())
	default:
		s.unavailable(w, CodePoliciesUnavailable, err)
	}
}

func policyRoutes(s *Server) []route {
	return []route{
		{http.MethodPost, AgentPoliciesPath, "agent_policy_publish", Permits(authz.Agents, authz.Write), s.publishPolicy()},
		{http.MethodPost, AgentPolicySearch, "agent_policy_search", Permits(authz.Agents, authz.Read), s.searchPolicies()},
		{http.MethodGet, AgentPolicyPath, "agent_policy_describe", Permits(authz.Agents, authz.Read), s.describePolicy()},
	}
}
