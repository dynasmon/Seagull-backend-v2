package control

import (
	"net/http"
	"time"

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

func (s *Server) describeToAgents(described *platformv1.Descriptor, tag string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := agentidentity.FromConnection(r.TLS); err != nil {
			Refuse(w, http.StatusUnauthorized, CodeNoCertificate, err.Error())
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
