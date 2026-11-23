package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

// What the agent listener offers an agent beside the gateway's streams, from
// what this plane was built with: renewal and the policy route always, since the
// listener exists to renew and is never built without a policy store, and
// updates only once a store and a root were given, which is when it hands one out.
func (s *Server) agentDescriptor() (*platformv1.Descriptor, string, error) {
	described := protocol.Descriptor(time.Time{})
	described.ServerTime = nil
	described.Capabilities = []*platformv1.Capability{
		{Name: protocol.CapabilityRenewal, Route: http.MethodPost + " " + RenewalPath},
		{Name: protocol.CapabilityPolicy, Route: http.MethodGet + " " + PolicyPath,
			SupportedSchema: &platformv1.VersionRange{Minimum: agentpolicy.SchemaVersion, Maximum: agentpolicy.SchemaVersion}},
	}
	if s.takesUpdates() {
		described.Capabilities = append(described.Capabilities, &platformv1.Capability{Name: protocol.CapabilityUpdate,
			Route:           http.MethodGet + " " + UpdatePath,
			SupportedSchema: &platformv1.VersionRange{Minimum: agentupdate.SchemaVersion, Maximum: agentupdate.SchemaVersion}})
	}
	tag, err := protocol.Tag(described)
	if err != nil {
		return nil, "", err
	}
	return described, tag, nil
}

// It stands behind the registry and a limiter, as the gateway's descriptor and
// every other route of this listener do, so a certificate the authority signed
// for an agent nobody registered, or one revoked since, learns nothing here.
func (s *Server) describeToAgents(described *platformv1.Descriptor, tag string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, err := agentidentity.FromConnection(r.TLS)
		if err != nil {
			Refuse(w, http.StatusUnauthorized, CodeNoCertificate, err.Error())
			return
		}
		if s.descriptions != nil && !s.descriptions.Allow(presented.AgentID) {
			Refuse(w, http.StatusTooManyRequests, CodeRateLimited, "this agent is asking what the listener serves too often")
			return
		}
		if !s.presents(w, r, presented, http.MethodGet+" "+DescriptorPath) {
			return
		}
		state, err := s.agents.State(r.Context(), presented.AgentID)
		switch {
		case errors.Is(err, agent.ErrUnknown):
			Refuse(w, http.StatusNotFound, CodeUnknownAgent, "no agent is registered under the identity this connection proved")
			return
		case err != nil:
			s.unavailable(w, CodeAgentsUnavailable, err)
			return
		case !state.Admits():
			Refuse(w, http.StatusForbidden, CodeNotAdmitted, "the platform no longer listens to this agent")
			return
		}
		w.Header().Set("ETag", tag)
		w.Header().Set("Cache-Control", "no-cache")
		if httpx.Unchanged(r, tag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		encoded, err := protocol.Answer(described, s.now())
		if err != nil {
			http.Error(w, "response encoding failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	})
}
