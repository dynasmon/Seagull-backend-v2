package control_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// Enough of an update store to prove the routes, enforcing what the PostgreSQL
// one enforces: roots and catalogs only move forward, a catalog names only
// packages it was given, and a version is assigned only to agents of the tenant
// while the newest catalog names it.
type stubUpdates struct {
	mu        sync.Mutex
	agents    *stubAgents
	roots     []agentupdate.AcceptedRoot
	packages  map[string][]byte
	catalogs  []agentupdate.AcceptedCatalog
	assigned  map[string]string
	entered   chan struct{}
	held      chan struct{}
	unreached error
}

func newStubUpdates(agents *stubAgents) *stubUpdates {
	return &stubUpdates{agents: agents, packages: map[string][]byte{}, assigned: map[string]string{}}
}

func (s *stubUpdates) Roots(_ context.Context, after uint64) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var served [][]byte
	for _, root := range s.roots {
		if root.Root.Version() > after {
			served = append(served, root.Root.Served())
		}
	}
	return served, s.unreached
}

func (s *stubUpdates) PublishRoot(_ context.Context, accepted agentupdate.AcceptedRoot) (*updatev1.PublishedRoot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, before := range s.roots {
		if before.Root.Version() >= accepted.Root.Version() {
			return nil, fmt.Errorf("%w: root %d", agentupdate.ErrStale, before.Root.Version())
		}
	}
	s.roots = append(s.roots, accepted)
	return accepted.Record, nil
}

func (s *stubUpdates) PublishPackage(_ context.Context, accepted agentupdate.AcceptedPackage) (*updatev1.PublishedPackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packages[hex.EncodeToString(accepted.Record.GetSha256())] = accepted.Content
	return accepted.Record, nil
}

func (s *stubUpdates) PublishCatalog(_ context.Context, accepted agentupdate.AcceptedCatalog) (*updatev1.PublishedCatalog, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, before := range s.catalogs {
		if before.Catalog.Version() >= accepted.Catalog.Version() {
			return nil, fmt.Errorf("%w: catalog %d", agentupdate.ErrStale, before.Catalog.Version())
		}
	}
	for _, named := range accepted.Packages {
		if content, given := s.packages[hex.EncodeToString(named.Sha256)]; !given || uint64(len(content)) != named.Size {
			return nil, fmt.Errorf("%w: %x", agentupdate.ErrNoPackage, named.Sha256)
		}
	}
	s.catalogs = append(s.catalogs, accepted)
	return accepted.Record, nil
}

func (s *stubUpdates) newest() *agentupdate.Catalog {
	if len(s.catalogs) == 0 {
		return nil
	}
	return s.catalogs[len(s.catalogs)-1].Catalog
}

func (s *stubUpdates) Assign(_ context.Context, accepted agentupdate.AcceptedAssignment) (*updatev1.Assigned, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if accepted.Version != "" && (s.newest() == nil || !s.newest().Names(accepted.Version)) {
		return nil, fmt.Errorf("%w: %s", agentupdate.ErrUncataloged, accepted.Version)
	}
	for _, id := range accepted.AgentIDs {
		if registered, known := s.agents.held[id]; !known || registered.GetTenantId() != accepted.TenantID {
			return nil, fmt.Errorf("%w: %s", agentupdate.ErrUnregistered, id)
		}
	}
	for _, id := range accepted.AgentIDs {
		if accepted.Version == "" {
			delete(s.assigned, id)
		} else {
			s.assigned[id] = accepted.Version
		}
	}
	return accepted.Record, nil
}

func (s *stubUpdates) Served(ctx context.Context, agentID string, after uint64) (agentupdate.Served, error) {
	registered, known := s.agents.held[agentID]
	if !known {
		return agentupdate.Served{}, agent.ErrUnknown
	}
	state, _ := agent.FromWire(registered.GetState())
	roots, err := s.Roots(ctx, after)
	if err != nil {
		return agentupdate.Served{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	served := agentupdate.Served{State: state, Roots: roots, Version: s.assigned[agentID]}
	if newest := s.newest(); newest != nil {
		served.Catalog = newest.Served()
	}
	return served, nil
}

func (s *stubUpdates) Package(_ context.Context, agentID string, digest []byte) (agentupdate.ServedPackage, error) {
	if s.held != nil {
		s.entered <- struct{}{}
		<-s.held
	}
	registered, known := s.agents.held[agentID]
	if !known {
		return agentupdate.ServedPackage{}, agent.ErrUnknown
	}
	state, _ := agent.FromWire(registered.GetState())
	if !state.Admits() {
		return agentupdate.ServedPackage{State: state}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if newest := s.newest(); newest != nil {
		for _, release := range newest.Releases() {
			if release.GetVersion() == s.assigned[agentID] && bytes.Equal(release.GetPayload().GetSha256(), digest) {
				return agentupdate.ServedPackage{State: state, Content: s.packages[hex.EncodeToString(digest)]}, nil
			}
		}
	}
	return agentupdate.ServedPackage{}, agentupdate.ErrUnknown
}

type updateKey struct {
	key *ecdsa.PrivateKey
	id  string
	der []byte
}

func newUpdateKey(t *testing.T) updateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate an update key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode an update key: %v", err)
	}
	return updateKey{key: key, id: agentupdate.KeyID(der), der: der}
}

func signedUpdate(t *testing.T, message proto.Message, payloadType string, keys ...updateKey) *updatev1.Envelope {
	t.Helper()
	signing := make([]crypto.Signer, 0, len(keys))
	for _, key := range keys {
		signing = append(signing, key.key)
	}
	envelope, err := agentupdate.Sign(message, payloadType, signing...)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return envelope
}

func updateRoot(t *testing.T, version uint64, owner, publisher updateKey, keys ...updateKey) *updatev1.Envelope {
	t.Helper()
	at := time.Now().UTC()
	root := &updatev1.Root{
		SchemaVersion: agentupdate.SchemaVersion,
		Version:       version,
		IssuedAt:      timestamppb.New(at.Add(-time.Hour)),
		ExpiresAt:     timestamppb.New(at.Add(180 * 24 * time.Hour)),
		Keys:          []*updatev1.Key{{Keyid: owner.id, PublicKey: owner.der}},
		Root:          &updatev1.Role{Keyids: []string{owner.id}, Threshold: 1},
		Catalog:       &updatev1.Role{Keyids: []string{publisher.id}, Threshold: 1},
	}
	if publisher.id != owner.id {
		root.Keys = append(root.Keys, &updatev1.Key{Keyid: publisher.id, PublicKey: publisher.der})
	}
	return signedUpdate(t, root, agentupdate.RootPayloadType, keys...)
}

func anchorOf(t *testing.T, envelope *updatev1.Envelope) func() (*agentupdate.Root, error) {
	t.Helper()
	served, err := agentupdate.Encode(envelope)
	if err != nil {
		t.Fatalf("encode the anchor: %v", err)
	}
	return func() (*agentupdate.Root, error) { return agentupdate.Anchor(served, time.Now()) }
}

func packageRelease(version string, content []byte) *updatev1.Release {
	sum := sha256.Sum256(content)
	return &updatev1.Release{
		Version:       version,
		Platform:      &updatev1.Platform{Os: "linux", Architecture: "amd64", Format: updatev1.Format_FORMAT_DEB},
		Payload:       &updatev1.Payload{Sha256: sum[:], Size: uint64(len(content))},
		Source:        &updatev1.Source{Repository: "github.com/dynasmon/Seagull-agent-v2", Revision: strings.Repeat("cd", 20)},
		Compatibility: &updatev1.Compatibility{StateGeneration: 1},
	}
}

func updateCatalog(t *testing.T, version uint64, publisher updateKey, releases ...*updatev1.Release) *updatev1.Envelope {
	t.Helper()
	at := time.Now().UTC()
	return signedUpdate(t, &updatev1.Catalog{
		SchemaVersion: agentupdate.SchemaVersion,
		Version:       version,
		IssuedAt:      timestamppb.New(at.Add(-time.Hour)),
		ExpiresAt:     timestamppb.New(at.Add(30 * 24 * time.Hour)),
		Releases:      releases,
	}, agentupdate.CatalogPayloadType, publisher)
}

func updateListener(t *testing.T, h *harness, held *stubAgents, store *stubUpdates, anchor func() (*agentupdate.Root, error)) http.Handler {
	t.Helper()
	signing, bundle := testAuthority(t)
	options := control.ServerOptions{
		Guard: h.guard, Sessions: h.sessions, Registry: h.registry,
		Rulesets: newStubRulesets(), Alerts: newStubAlerts(), Incidents: newStubIncidents(),
		Agents: held, Admissions: &stubAdmissions{}, Policies: newStubPolicies(held), UpdateRoot: anchor,
		Authority: signing, TrustBundle: bundle, CertificateLife: time.Hour,
		Metrics: h.metrics, Logger: slog.New(slog.DiscardHandler),
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-updates")),
	}
	if store != nil {
		options.Updates = store
	}
	handler, err := control.NewHandler(options)
	if err != nil {
		t.Fatalf("build the routes: %v", err)
	}
	return handler
}

func updateFacing(t *testing.T, held *stubAgents, store *stubUpdates, anchor func() (*agentupdate.Root, error), limiter *ratelimit.Limiter) http.Handler {
	t.Helper()
	signing, bundle := testAuthority(t)
	handler, err := control.NewRenewalHandler(control.ServerOptions{
		Agents: held, Policies: newStubPolicies(held), Updates: store, UpdateRoot: anchor, UpdateLimiter: limiter,
		Authority: signing, TrustBundle: bundle, CertificateLife: time.Hour,
		Metrics:         control.NewMetrics(metrics.New("control-api-agent-updates")),
		Logger:          slog.New(slog.DiscardHandler),
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-agent-update-routes")),
	})
	if err != nil {
		t.Fatalf("build the agent listener: %v", err)
	}
	return handler
}

func upload(t *testing.T, handler http.Handler, subject, token string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, control.UpdatePackagesPath, bytes.NewReader(content))
	r.TLS = request(t, subject, "").TLS
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", control.PackageContentType)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

func askUpdate(t *testing.T, handler http.Handler, subject, unchanged string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, control.UpdatePath, nil)
	r.TLS = request(t, subject, "").TLS
	if unchanged != "" {
		r.Header.Set("If-None-Match", unchanged)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

func askPackage(t *testing.T, handler http.Handler, subject, digest string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v1/agents/update/packages/"+digest, nil)
	r.TLS = request(t, subject, "").TLS
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// An estate where root 1 is configured, root 2 and a package were published,
// and catalog 1 names that package as v0.2.0.
type publishedUpdates struct {
	owner, publisher updateKey
	anchor           func() (*agentupdate.Root, error)
	store            *stubUpdates
	held             *stubAgents
	content          []byte
}

func publishUpdates(t *testing.T, h *harness) publishedUpdates {
	t.Helper()
	owner, publisher := newUpdateKey(t), newUpdateKey(t)
	held := newStubAgents()
	published := publishedUpdates{
		owner: owner, publisher: publisher,
		anchor:  anchorOf(t, updateRoot(t, 1, owner, publisher, owner)),
		store:   newStubUpdates(held),
		held:    held,
		content: []byte("!<arch>\nthe package of v0.2.0"),
	}
	handler := updateListener(t, h, held, published.store, published.anchor)
	admin := open(t, h, "dev-admin")

	if recorder := call(t, handler, http.MethodPost, control.UpdateRootsPath, "dev-admin", admin,
		&updatev1.RootPublication{Root: updateRoot(t, 2, owner, publisher, owner), Note: "a year more"}); recorder.Code != http.StatusCreated {
		t.Fatalf("publishing root 2 answered %d: %s", recorder.Code, recorder.Body)
	}
	if recorder := upload(t, handler, "dev-admin", admin, published.content); recorder.Code != http.StatusCreated {
		t.Fatalf("giving the package answered %d: %s", recorder.Code, recorder.Body)
	}
	if recorder := call(t, handler, http.MethodPost, control.UpdateCatalogsPath, "dev-admin", admin,
		&updatev1.CatalogPublication{Catalog: updateCatalog(t, 1, publisher, packageRelease("v0.2.0", published.content))}); recorder.Code != http.StatusCreated {
		t.Fatalf("publishing catalog 1 answered %d: %s", recorder.Code, recorder.Body)
	}
	return published
}

func TestAnAdministratorPublishesWhatAuthorizesAnUpdateAndAssignsIt(t *testing.T) {
	h := newHarness(t, nil)
	published := publishUpdates(t, h)
	handler := updateListener(t, h, published.held, published.store, published.anchor)
	admin := open(t, h, "dev-admin")

	recorder := call(t, handler, http.MethodPost, control.UpdateAssignmentsPath, "dev-admin", admin,
		&updatev1.Assignment{TenantId: "default", AgentIds: []string{"web-01"}, Version: "v0.2.0", Note: "canary"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("assigning answered %d: %s", recorder.Code, recorder.Body)
	}
	var assigned updatev1.Assigned
	decode(t, recorder, &assigned)
	if assigned.GetAgents() != 1 || assigned.GetVersion() != "v0.2.0" || assigned.GetAssignedBy() != "dev-admin" || assigned.GetNote() != "canary" {
		t.Fatalf("assigned %v", &assigned)
	}

	root, catalog := published.store.roots[0].Record, published.store.catalogs[0].Record
	switch {
	case root.GetVersion() != 2 || root.GetPublishedBy() != "dev-admin" || !slices.Equal(root.GetSignedBy(), []string{published.owner.id}):
		t.Fatalf("root recorded as %v", root)
	case catalog.GetVersion() != 1 || catalog.GetReleases() != 1 || !slices.Equal(catalog.GetSignedBy(), []string{published.publisher.id}):
		t.Fatalf("catalog recorded as %v", catalog)
	case published.store.assigned["web-01"] != "v0.2.0":
		t.Fatalf("assignments held %v", published.store.assigned)
	}
}

func TestAControlPlaneGivenNoRootTakesAndOffersNoUpdate(t *testing.T) {
	h, held := newHarness(t, nil), newStubAgents()
	store := newStubUpdates(held)
	owner := newUpdateKey(t)
	admin := open(t, h, "dev-admin")

	for _, handler := range []http.Handler{updateListener(t, h, held, store, nil), updateListener(t, h, held, nil, anchorOf(t, updateRoot(t, 1, owner, owner, owner)))} {
		refusedWith(t, call(t, handler, http.MethodPost, control.UpdateRootsPath, "dev-admin", admin,
			&updatev1.RootPublication{Root: updateRoot(t, 2, owner, owner, owner)}), http.StatusServiceUnavailable, control.CodeUpdatesUnconfigured)
		refusedWith(t, upload(t, handler, "dev-admin", admin, []byte("package")), http.StatusServiceUnavailable, control.CodeUpdatesUnconfigured)
		refusedWith(t, call(t, handler, http.MethodPost, control.UpdateCatalogsPath, "dev-admin", admin,
			&updatev1.CatalogPublication{Catalog: updateCatalog(t, 1, owner)}), http.StatusServiceUnavailable, control.CodeUpdatesUnconfigured)
		refusedWith(t, call(t, handler, http.MethodPost, control.UpdateAssignmentsPath, "dev-admin", admin,
			&updatev1.Assignment{TenantId: "default", AgentIds: []string{"web-01"}, Version: "v0.2.0"}), http.StatusServiceUnavailable, control.CodeUpdatesUnconfigured)
	}

	facing := updateFacing(t, held, store, nil, nil)
	refusedWith(t, askUpdate(t, facing, "web-01", ""), http.StatusNotFound, control.CodeUpdatesUnconfigured)
	refusedWith(t, askPackage(t, facing, "web-01", digestOf([]byte("package"))), http.StatusNotFound, control.CodeUnknownPackage)
}

func TestTakingUpdatesNeedsToWriteAgentsAndAnAssignmentTheTenantToo(t *testing.T) {
	h := newHarness(t, nil)
	published := publishUpdates(t, h)
	handler := updateListener(t, h, published.held, published.store, published.anchor)
	analyst := open(t, h, "dev-analyst")

	refusedWith(t, call(t, handler, http.MethodPost, control.UpdateCatalogsPath, "dev-analyst", analyst,
		&updatev1.CatalogPublication{Catalog: updateCatalog(t, 2, published.publisher)}), http.StatusForbidden, control.CodeForbidden)
	refusedWith(t, call(t, handler, http.MethodPost, control.UpdateAssignmentsPath, "dev-admin", open(t, h, "dev-admin"),
		&updatev1.Assignment{TenantId: "another", AgentIds: []string{"web-01"}, Version: "v0.2.0"}), http.StatusForbidden, control.CodeForbidden)
}

func TestWhatNoRoleSignedOrThatWouldGoBackwardsIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	published := publishUpdates(t, h)
	handler := updateListener(t, h, published.held, published.store, published.anchor)
	admin := open(t, h, "dev-admin")
	stranger := newUpdateKey(t)
	other := []byte("!<arch>\nthe package of v0.3.0")

	for name, refused := range map[string]struct {
		path   string
		body   proto.Message
		status int
		code   string
	}{
		"a catalog a stranger signed": {control.UpdateCatalogsPath, &updatev1.CatalogPublication{Catalog: updateCatalog(t, 2, stranger)},
			http.StatusUnprocessableEntity, control.CodeUpdateUnsigned},
		"a catalog signed by the root role": {control.UpdateCatalogsPath, &updatev1.CatalogPublication{Catalog: updateCatalog(t, 2, published.owner)},
			http.StatusUnprocessableEntity, control.CodeUpdateUnsigned},
		"a catalog that does not move forward": {control.UpdateCatalogsPath, &updatev1.CatalogPublication{Catalog: updateCatalog(t, 1, published.publisher)},
			http.StatusConflict, control.CodeUpdateStale},
		"a catalog naming a package nobody gave": {control.UpdateCatalogsPath,
			&updatev1.CatalogPublication{Catalog: updateCatalog(t, 2, published.publisher, packageRelease("v0.3.0", other))},
			http.StatusUnprocessableEntity, control.CodeUpdatePackageAbsent},
		"a root that skips a version": {control.UpdateRootsPath,
			&updatev1.RootPublication{Root: updateRoot(t, 4, published.owner, published.publisher, published.owner)},
			http.StatusUnprocessableEntity, control.CodeMalformedUpdate},
		"the root already held": {control.UpdateRootsPath,
			&updatev1.RootPublication{Root: updateRoot(t, 2, published.owner, published.publisher, published.owner)},
			http.StatusConflict, control.CodeUpdateStale},
		"a root the newest one did not vouch for": {control.UpdateRootsPath,
			&updatev1.RootPublication{Root: updateRoot(t, 3, stranger, stranger, stranger)},
			http.StatusUnprocessableEntity, control.CodeUpdateUnsigned},
		"a version no catalog names": {control.UpdateAssignmentsPath,
			&updatev1.Assignment{TenantId: "default", AgentIds: []string{"web-01"}, Version: "v0.3.0"},
			http.StatusUnprocessableEntity, control.CodeReleaseUncataloged},
		"an agent the tenant does not hold": {control.UpdateAssignmentsPath,
			&updatev1.Assignment{TenantId: "default", AgentIds: []string{"web-01", "web-77"}, Version: "v0.2.0"},
			http.StatusUnprocessableEntity, control.CodeUpdateUnregistered},
	} {
		t.Run(name, func(t *testing.T) {
			refusedWith(t, call(t, handler, http.MethodPost, refused.path, "dev-admin", admin, refused.body), refused.status, refused.code)
		})
	}
	if len(published.store.roots) != 1 || len(published.store.catalogs) != 1 || len(published.store.assigned) != 0 {
		t.Fatalf("a refusal changed what the store holds: %d roots, %d catalogs, %d assignments",
			len(published.store.roots), len(published.store.catalogs), len(published.store.assigned))
	}
}

func TestAnAgentIsOfferedTheRootsTheNewestCatalogAndItsVersionAsTheyWereRecorded(t *testing.T) {
	h := newHarness(t, nil)
	published := publishUpdates(t, h)
	published.store.assigned["web-01"] = "v0.2.0"
	anchor, err := published.anchor()
	if err != nil {
		t.Fatal(err)
	}
	facing := updateFacing(t, published.held, published.store, published.anchor, nil)

	recorder := askUpdate(t, facing, "web-01", "")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != control.ContentType {
		t.Fatalf("the agent was answered %d as %q: %s", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body)
	}
	var offer updatev1.Offer
	decode(t, recorder, &offer)
	encode := func(envelope *updatev1.Envelope) []byte {
		served, err := agentupdate.Encode(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return served
	}
	switch {
	case len(offer.GetRoots()) != 2 || !bytes.Equal(encode(offer.GetRoots()[0]), anchor.Served()) ||
		!bytes.Equal(encode(offer.GetRoots()[1]), published.store.roots[0].Root.Served()):
		t.Fatalf("offered %d roots, not the chain as recorded", len(offer.GetRoots()))
	case !bytes.Equal(encode(offer.GetCatalog()), published.store.catalogs[0].Catalog.Served()):
		t.Fatal("offered a catalog other than the newest as recorded")
	case offer.GetVersion() != "v0.2.0":
		t.Fatalf("offered version %q", offer.GetVersion())
	case recorder.Header().Get("ETag") != strconv.Quote(agentupdate.Digest(recorder.Body.Bytes())):
		t.Fatalf("the offer was tagged %q", recorder.Header().Get("ETag"))
	}

	tag := recorder.Header().Get("ETag")
	if again := askUpdate(t, facing, "web-01", tag); again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Fatalf("asking with the tag held was answered %d", again.Code)
	}
	published.store.assigned["web-01"] = ""
	if changed := askUpdate(t, facing, "web-01", tag); changed.Code != http.StatusOK {
		t.Fatalf("asking after the assignment changed was answered %d", changed.Code)
	}
}

func TestAnAgentIsHandedOnlyThePackageOfTheReleaseItWasAssigned(t *testing.T) {
	h := newHarness(t, nil)
	published := publishUpdates(t, h)
	facing := updateFacing(t, published.held, published.store, published.anchor, nil)
	digest := digestOf(published.content)

	refusedWith(t, askPackage(t, facing, "web-01", digest), http.StatusNotFound, control.CodeUnknownPackage)
	published.store.assigned["web-01"] = "v0.2.0"
	recorder := askPackage(t, facing, "web-01", digest)
	switch {
	case recorder.Code != http.StatusOK:
		t.Fatalf("the package was answered %d: %s", recorder.Code, recorder.Body)
	case !bytes.Equal(recorder.Body.Bytes(), published.content):
		t.Fatal("the package was not handed over as it was given")
	case recorder.Header().Get("Content-Length") != strconv.Itoa(len(published.content)) || recorder.Header().Get("Content-Type") != control.PackageContentType:
		t.Fatalf("the package was answered as %q of %q bytes", recorder.Header().Get("Content-Type"), recorder.Header().Get("Content-Length"))
	}

	for _, asked := range []string{digestOf([]byte("another package")), strings.ToUpper(digest), digest[:63], "not-a-digest"} {
		refusedWith(t, askPackage(t, facing, "web-01", asked), http.StatusNotFound, control.CodeUnknownPackage)
	}
	refusedWith(t, askPackage(t, facing, "web-77", digest), http.StatusNotFound, control.CodeUnknownAgent)
	if _, err := published.held.Move(t.Context(), "web-01", []string{"default"}, agent.Move{
		To: agent.Disabled, Note: "the machine is being rebuilt", Actor: "dev-admin", At: published.held.clock,
	}); err != nil {
		t.Fatalf("disable the agent: %v", err)
	}
	refusedWith(t, askPackage(t, facing, "web-01", digest), http.StatusForbidden, control.CodeNotAdmitted)
	refusedWith(t, askUpdate(t, facing, "web-01", ""), http.StatusForbidden, control.CodeNotAdmitted)
}

func TestAnAgentAskingAboutUpdatesTooOftenIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	published := publishUpdates(t, h)
	facing := updateFacing(t, published.held, published.store, published.anchor, ratelimit.NewLimiter(0.001, 1, 16))

	if recorder := askUpdate(t, facing, "web-01", ""); recorder.Code != http.StatusOK {
		t.Fatalf("the first request was answered %d", recorder.Code)
	}
	refusedWith(t, askUpdate(t, facing, "web-01", ""), http.StatusTooManyRequests, control.CodeRateLimited)
}

func TestNoMoreAgentsDownloadAtOnceThanThePlatformServes(t *testing.T) {
	h := newHarness(t, nil)
	published := publishUpdates(t, h)
	published.store.assigned["web-01"] = "v0.2.0"
	published.store.entered = make(chan struct{}, control.MaxDownloads)
	published.store.held = make(chan struct{})
	facing := updateFacing(t, published.held, published.store, published.anchor, nil)
	digest := digestOf(published.content)

	var downloading sync.WaitGroup
	defer downloading.Wait()
	defer close(published.store.held)
	for range control.MaxDownloads {
		downloading.Go(func() {
			if recorder := askPackage(t, facing, "web-01", digest); recorder.Code != http.StatusOK {
				t.Errorf("a download within the bound was answered %d", recorder.Code)
			}
		})
	}
	for range control.MaxDownloads {
		select {
		case <-published.store.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the downloads within the bound never began")
		}
	}
	refusedWith(t, askPackage(t, facing, "web-01", digest), http.StatusTooManyRequests, control.CodeRateLimited)
}
