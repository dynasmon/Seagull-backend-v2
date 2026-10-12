package control

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const (
	UpdateRootsPath       = "/v1/agents/update/roots"
	UpdatePackagesPath    = "/v1/agents/update/packages"
	UpdateCatalogsPath    = "/v1/agents/update/catalogs"
	UpdateAssignmentsPath = "/v1/agents/update/assignments"
	UpdatePath            = "/v1/agents/update"
	UpdatePackagePath     = "/v1/agents/update/packages/{sha256}"

	PackageContentType = "application/octet-stream"

	MaxUpdateBodyBytes     = agentupdate.MaxEnvelopeBytes + 4<<10
	MaxAssignmentBodyBytes = 1 << 20
	MaxDownloads           = 4

	transferRate  = 256 << 10
	transferGrace = 30 * time.Second
)

// Where the platform keeps what authorizes an update and what it decided about
// one. It signs none of it: what is stored was verified under a root the
// platform holds no key of, and an agent verifies it again under its own.
type AgentUpdates interface {
	Roots(ctx context.Context, after uint64) ([][]byte, error)
	PublishRoot(ctx context.Context, accepted agentupdate.AcceptedRoot) (*updatev1.PublishedRoot, error)
	PublishPackage(ctx context.Context, accepted agentupdate.AcceptedPackage) (*updatev1.PublishedPackage, error)
	PublishCatalog(ctx context.Context, accepted agentupdate.AcceptedCatalog) (*updatev1.PublishedCatalog, error)
	Assign(ctx context.Context, accepted agentupdate.AcceptedAssignment) (*updatev1.Assigned, error)
	Served(ctx context.Context, agentID string, after uint64) (agentupdate.Served, error)
	Package(ctx context.Context, agentID string, digest []byte) (agentupdate.ServedPackage, error)
}

// The newest root the platform trusts: the one it was configured with, walked
// through every root recorded after it.
func (s *Server) newestRoot(ctx context.Context) (*agentupdate.Root, error) {
	anchor, err := s.updateRoot()
	if err != nil {
		return nil, err
	}
	recorded, err := s.updates.Roots(ctx, anchor.Version())
	if err != nil {
		return nil, err
	}
	return anchor.Walk(recorded, s.now())
}

// Updates are taken only by a control plane given both a root to verify them
// against and somewhere to keep them.
func (s *Server) takesUpdates() bool { return s.updates != nil && s.updateRoot != nil }

func (s *Server) updatesConfigured(w http.ResponseWriter, kind string) bool {
	if !s.takesUpdates() {
		s.metrics.updatePublished(kind, "unconfigured")
		Refuse(w, http.StatusServiceUnavailable, CodeUpdatesUnconfigured,
			"this control plane was given no update root to verify against, so it takes no update")
		return false
	}
	return true
}

func (s *Server) publishUpdateRoot() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		var asked updatev1.RootPublication
		if !readWithin(w, r, &asked, MaxUpdateBodyBytes) || !s.updatesConfigured(w, "root") {
			return
		}
		newest, err := s.newestRoot(r.Context())
		if err != nil {
			s.metrics.updatePublished("root", "refused")
			s.refuseUpdate(w, err)
			return
		}
		accepted, err := agentupdate.AcceptRoot(&asked, newest, caller.Subject, s.now())
		if err == nil {
			_, err = s.updates.PublishRoot(r.Context(), accepted)
		}
		if err != nil {
			s.metrics.updatePublished("root", "refused")
			s.refuseUpdate(w, err)
			return
		}
		recorded := accepted.Record
		s.metrics.updatePublished("root", "published")
		s.logger.Info("agent_update_root_published",
			slog.Uint64("version", recorded.GetVersion()),
			slog.String("digest_sha256", recorded.GetDigestSha256()),
			slog.Any("signed_by", recorded.GetSignedBy()),
			slog.String("published_by", recorded.GetPublishedBy()),
			slog.Time("expires_at", recorded.GetExpiresAt().AsTime()),
		)
		respond(w, http.StatusCreated, recorded)
	})
}

// The package is read whole within its ceiling, and given longer to arrive than
// a request is, at a rate no slower than an agent would download it.
func (s *Server) publishPackage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		if !s.updatesConfigured(w, "package") {
			return
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(transferTime(agentupdate.MaxPackageBytes)))
		content, err := io.ReadAll(http.MaxBytesReader(w, r.Body, agentupdate.MaxPackageBytes))
		if err != nil {
			s.metrics.updatePublished("package", "refused")
			Refuse(w, http.StatusRequestEntityTooLarge, "body_too_large", "the package is larger than a package may be")
			return
		}
		accepted, err := agentupdate.AcceptPackage(content, caller.Subject, s.now())
		if err != nil {
			s.metrics.updatePublished("package", "refused")
			s.refuseUpdate(w, err)
			return
		}
		recorded, err := s.updates.PublishPackage(r.Context(), accepted)
		if err != nil {
			s.metrics.updatePublished("package", "refused")
			s.refuseUpdate(w, err)
			return
		}
		s.metrics.updatePublished("package", "published")
		s.logger.Info("agent_package_published",
			slog.String("sha256", hex.EncodeToString(recorded.GetSha256())),
			slog.Uint64("size", recorded.GetSize()),
			slog.String("published_by", recorded.GetPublishedBy()),
		)
		respond(w, http.StatusCreated, recorded)
	})
}

func (s *Server) publishUpdateCatalog() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		var asked updatev1.CatalogPublication
		if !readWithin(w, r, &asked, MaxUpdateBodyBytes) || !s.updatesConfigured(w, "catalog") {
			return
		}
		newest, err := s.newestRoot(r.Context())
		if err != nil {
			s.metrics.updatePublished("catalog", "refused")
			s.refuseUpdate(w, err)
			return
		}
		accepted, err := agentupdate.AcceptCatalog(&asked, newest, caller.Subject, s.now())
		if err == nil {
			_, err = s.updates.PublishCatalog(r.Context(), accepted)
		}
		if err != nil {
			s.metrics.updatePublished("catalog", "refused")
			s.refuseUpdate(w, err)
			return
		}
		recorded := accepted.Record
		s.metrics.updatePublished("catalog", "published")
		s.logger.Info("agent_update_catalog_published",
			slog.Uint64("version", recorded.GetVersion()),
			slog.Uint64("releases", uint64(recorded.GetReleases())),
			slog.String("digest_sha256", recorded.GetDigestSha256()),
			slog.Any("signed_by", recorded.GetSignedBy()),
			slog.String("published_by", recorded.GetPublishedBy()),
			slog.Time("expires_at", recorded.GetExpiresAt().AsTime()),
		)
		respond(w, http.StatusCreated, recorded)
	})
}

func (s *Server) assignRelease() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, known := CallerFrom(r.Context())
		if !known {
			Refuse(w, http.StatusUnauthorized, CodeNoSession, "the request did not come through the guard")
			return
		}
		var asked updatev1.Assignment
		if !readWithin(w, r, &asked, MaxAssignmentBodyBytes) {
			return
		}
		decision := caller.Grant.DecideWithin(
			authz.Permission{Resource: authz.Agents, Action: authz.Write}, asked.GetTenantId())
		s.metrics.decided(decision)
		if !decision.Allowed() {
			Refuse(w, http.StatusForbidden, CodeForbidden,
				"assigning a release to agents of "+asked.GetTenantId()+" needs "+decision.Permission.String()+" there")
			return
		}
		if !s.updatesConfigured(w, "assignment") {
			return
		}
		accepted, err := agentupdate.AcceptAssignment(&asked, caller.Subject, s.now())
		if err == nil {
			_, err = s.updates.Assign(r.Context(), accepted)
		}
		if err != nil {
			s.metrics.updatePublished("assignment", "refused")
			s.refuseUpdate(w, err)
			return
		}
		recorded := accepted.Record
		s.metrics.updatePublished("assignment", "published")
		s.logger.Info("agent_release_assigned",
			slog.String("tenant_id", recorded.GetTenantId()),
			slog.String("version", recorded.GetVersion()),
			slog.Uint64("agents", uint64(recorded.GetAgents())),
			slog.String("assigned_by", recorded.GetAssignedBy()),
		)
		respond(w, http.StatusOK, recorded)
	})
}

// The agent is whoever the connection proved, and what it is handed is every
// root and the newest catalog exactly as they were recorded. The platform
// vouches for none of it: the agent checks every signature against the root it
// was provisioned with, so a platform that answers with anything else is
// refused by every agent.
func (s *Server) serveUpdate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, err := agentidentity.FromConnection(r.TLS)
		if err != nil {
			s.metrics.updateOffered("unidentified")
			Refuse(w, http.StatusUnauthorized, CodeNoCertificate, err.Error())
			return
		}
		if s.updatePulls != nil && !s.updatePulls.Allow(presented.AgentID) {
			s.metrics.updateOffered("rate_limited")
			Refuse(w, http.StatusTooManyRequests, CodeRateLimited, "this agent is asking whether to update too often")
			return
		}
		if !s.takesUpdates() {
			s.metrics.updateOffered("unconfigured")
			Refuse(w, http.StatusNotFound, CodeUpdatesUnconfigured, "this platform hands out no update")
			return
		}
		anchor, err := s.updateRoot()
		if err != nil {
			s.metrics.updateOffered("unavailable")
			s.unavailable(w, CodeUpdatesUnavailable, err)
			return
		}

		served, err := s.updates.Served(r.Context(), presented.AgentID, anchor.Version())
		switch {
		case errors.Is(err, agent.ErrUnknown):
			s.metrics.updateOffered("unknown")
			Refuse(w, http.StatusNotFound, CodeUnknownAgent, "no agent is registered under the identity this connection proved")
			return
		case err != nil:
			s.metrics.updateOffered("unavailable")
			s.unavailable(w, CodeUpdatesUnavailable, err)
			return
		case !served.State.Admits():
			s.metrics.updateOffered("not_admitted")
			Refuse(w, http.StatusForbidden, CodeNotAdmitted, "the platform no longer listens to this agent")
			return
		}
		served.Roots = append([][]byte{anchor.Served()}, served.Roots...)
		offer, err := served.Offer()
		if err != nil {
			s.metrics.updateOffered("unavailable")
			s.unavailable(w, CodeUpdatesUnavailable, err)
			return
		}

		tag := strconv.Quote(agentupdate.Digest(offer))
		w.Header().Set("ETag", tag)
		w.Header().Set("Cache-Control", "no-store")
		if unchanged(r.Header.Get("If-None-Match"), tag) {
			s.metrics.updateOffered("unchanged")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		s.metrics.updateOffered("offered")
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(offer)
	})
}

// A package is handed only to an agent assigned a release the newest catalog
// names it for, by as few agents at once as the process can hold in memory.
func (s *Server) servePackage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, err := agentidentity.FromConnection(r.TLS)
		if err != nil {
			s.metrics.packageServed("unidentified")
			Refuse(w, http.StatusUnauthorized, CodeNoCertificate, err.Error())
			return
		}
		if s.updatePulls != nil && !s.updatePulls.Allow(presented.AgentID) {
			s.metrics.packageServed("rate_limited")
			Refuse(w, http.StatusTooManyRequests, CodeRateLimited, "this agent is asking for packages too often")
			return
		}
		digest, err := hex.DecodeString(r.PathValue("sha256"))
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != r.PathValue("sha256") || !s.takesUpdates() {
			s.metrics.packageServed("unknown")
			Refuse(w, http.StatusNotFound, CodeUnknownPackage, "no package is held under that digest for this agent")
			return
		}
		select {
		case s.downloads <- struct{}{}:
			defer func() { <-s.downloads }()
		default:
			s.metrics.packageServed("busy")
			w.Header().Set("Retry-After", "30")
			Refuse(w, http.StatusTooManyRequests, CodeRateLimited, "as many agents as the platform serves at once are downloading")
			return
		}

		served, err := s.updates.Package(r.Context(), presented.AgentID, digest)
		switch {
		case errors.Is(err, agent.ErrUnknown):
			s.metrics.packageServed("unknown_agent")
			Refuse(w, http.StatusNotFound, CodeUnknownAgent, "no agent is registered under the identity this connection proved")
			return
		case errors.Is(err, agentupdate.ErrUnknown):
			s.metrics.packageServed("unknown")
			Refuse(w, http.StatusNotFound, CodeUnknownPackage, "no package is held under that digest for this agent")
			return
		case err != nil:
			s.metrics.packageServed("unavailable")
			s.unavailable(w, CodeUpdatesUnavailable, err)
			return
		case !served.State.Admits():
			s.metrics.packageServed("not_admitted")
			Refuse(w, http.StatusForbidden, CodeNotAdmitted, "the platform no longer listens to this agent")
			return
		}

		s.metrics.packageServed("served")
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(transferTime(len(served.Content))))
		w.Header().Set("Content-Type", PackageContentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(served.Content)))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(served.Content)
	})
}

func transferTime(size int) time.Duration {
	return transferGrace + time.Duration(size/transferRate)*time.Second
}

func (s *Server) refuseUpdate(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, agentupdate.ErrUnsigned):
		Refuse(w, http.StatusUnprocessableEntity, CodeUpdateUnsigned, err.Error())
	case errors.Is(err, agentupdate.ErrExpired):
		Refuse(w, http.StatusUnprocessableEntity, CodeUpdateExpired, err.Error())
	case errors.Is(err, agentupdate.ErrMalformed), errors.Is(err, agentupdate.ErrNoActor):
		Refuse(w, http.StatusUnprocessableEntity, CodeMalformedUpdate, err.Error())
	case errors.Is(err, agentupdate.ErrStale):
		Refuse(w, http.StatusConflict, CodeUpdateStale, err.Error())
	case errors.Is(err, agentupdate.ErrNoPackage):
		Refuse(w, http.StatusUnprocessableEntity, CodeUpdatePackageAbsent, err.Error())
	case errors.Is(err, agentupdate.ErrUncataloged):
		Refuse(w, http.StatusUnprocessableEntity, CodeReleaseUncataloged, err.Error())
	case errors.Is(err, agentupdate.ErrUnregistered):
		Refuse(w, http.StatusUnprocessableEntity, CodeUpdateUnregistered, err.Error())
	case errors.Is(err, agentupdate.ErrRoot):
		s.unavailable(w, CodeUpdatesUnconfigured, err)
	default:
		s.unavailable(w, CodeUpdatesUnavailable, err)
	}
}

func updateRoutes(s *Server) []route {
	return []route{
		{http.MethodPost, UpdateRootsPath, "agent_update_root_publish", Permits(authz.Agents, authz.Write), s.publishUpdateRoot()},
		{http.MethodPost, UpdatePackagesPath, "agent_package_publish", Permits(authz.Agents, authz.Write), s.publishPackage()},
		{http.MethodPost, UpdateCatalogsPath, "agent_update_catalog_publish", Permits(authz.Agents, authz.Write), s.publishUpdateCatalog()},
		{http.MethodPost, UpdateAssignmentsPath, "agent_release_assign", Permits(authz.Agents, authz.Write), s.assignRelease()},
	}
}
